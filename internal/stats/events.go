package stats

import (
	"sync"
	"time"
)

// EventType classifies an entry in the audit log.
type EventType string

// The event types the pool records.
const (
	EventAssignment  EventType = "assignment"
	EventRotate      EventType = "rotate"
	EventQuarantine  EventType = "quarantine"
	EventRemediation EventType = "remediation"
	EventRestart     EventType = "restart"
	EventResize      EventType = "resize"
	EventInstance    EventType = "instance"
	EventTorLog      EventType = "tor"

	// EventAuth records operator actions only — a sign-in, a token issued or
	// revoked. Rejected proxy credentials are logged to stderr instead: this ring
	// is bounded, so one entry per refused connection would let anyone flush the
	// audit history in seconds, exactly when it is worth reading.
	EventAuth EventType = "auth"
)

// Event is one entry in the audit log — a record of something the pool decided
// or was told to do, and why.
type Event struct {
	Seq      uint64    `json:"seq"`
	At       time.Time `json:"at"`
	Type     EventType `json:"type"`
	Instance *int      `json:"instance,omitempty"`
	Session  string    `json:"session,omitempty"`
	Message  string    `json:"message"`
	Detail   string    `json:"detail,omitempty"`
}

// EventLog is a bounded, in-memory ring of events with fan-out to subscribers.
type EventLog struct {
	mu     sync.RWMutex
	events []Event
	next   int
	full   bool
	seq    uint64

	subscribers map[int]chan Event
	nextSubID   int
}

// NewEventLog builds a log retaining the most recent size events.
func NewEventLog(size int) *EventLog {
	return &EventLog{
		events:      make([]Event, size),
		subscribers: make(map[int]chan Event),
	}
}

// Add records an event and fans it out to subscribers.
func (l *EventLog) Add(e Event) {
	l.mu.Lock()
	l.seq++
	e.Seq = l.seq
	if e.At.IsZero() {
		e.At = time.Now()
	}

	l.events[l.next] = e
	l.next = (l.next + 1) % len(l.events)
	if l.next == 0 {
		l.full = true
	}

	subs := make([]chan Event, 0, len(l.subscribers))
	for _, ch := range l.subscribers {
		subs = append(subs, ch)
	}
	l.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- e:
		default:
			// A subscriber that cannot keep up loses events rather than
			// blocking the pool. A stalled dashboard must never apply
			// backpressure to traffic.
		}
	}
}

// Instance records an event attributed to an instance.
func (l *EventLog) Instance(t EventType, instance int, message, detail string) {
	l.Add(Event{Type: t, Instance: &instance, Message: message, Detail: detail})
}

// Session records an event attributed to a session.
func (l *EventLog) Session(t EventType, session string, instance int, message string) {
	l.Add(Event{Type: t, Session: session, Instance: &instance, Message: message})
}

// Recent returns up to limit of the newest events, newest first.
func (l *EventLog) Recent(limit int) []Event {
	l.mu.RLock()
	defer l.mu.RUnlock()

	size := len(l.events)
	count := l.next
	if l.full {
		count = size
	}
	if limit <= 0 || limit > count {
		limit = count
	}

	out := make([]Event, 0, limit)
	for i := range limit {
		// Walk backwards from the newest.
		idx := (l.next - 1 - i + size) % size
		out = append(out, l.events[idx])
	}
	return out
}

// Subscribe returns a channel of future events and a function to release it.
//
// The channel is buffered and lossy on overflow; see Add.
func (l *EventLog) Subscribe(buffer int) (events <-chan Event, release func()) {
	ch := make(chan Event, buffer)

	l.mu.Lock()
	id := l.nextSubID
	l.nextSubID++
	l.subscribers[id] = ch
	l.mu.Unlock()

	return ch, func() {
		l.mu.Lock()
		delete(l.subscribers, id)
		l.mu.Unlock()
		close(ch)
	}
}
