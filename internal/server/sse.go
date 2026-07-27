package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	// streamInterval is how often a state snapshot is pushed.
	streamInterval = time.Second

	// eventBuffer is how many events a stream may fall behind by before it
	// starts dropping them. A stalled browser must never slow the pool down.
	eventBuffer = 64
)

// streamFrame is one SSE payload.
type streamFrame struct {
	Pool      PoolView       `json:"pool"`
	Instances []InstanceView `json:"instances"`
	Sample    any            `json:"sample"`
}

// handleStream pushes pool state to the dashboard over Server-Sent Events.
//
// SSE rather than a WebSocket: the traffic is entirely one-way, and SSE
// reconnects on its own with no client-side plumbing.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// Without this an intervening proxy may buffer the stream into uselessness.
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	events, unsubscribe := s.pool.Events().Subscribe(eventBuffer)
	defer unsubscribe()

	// Send state immediately so the dashboard paints without waiting a tick.
	if !s.writeState(w, flusher) {
		return
	}

	ticker := time.NewTicker(streamInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return

		case e, open := <-events:
			if !open {
				return
			}
			if !writeSSE(w, flusher, "event", e) {
				return
			}

		case <-ticker.C:
			if !s.writeState(w, flusher) {
				return
			}
		}
	}
}

func (s *Server) writeState(w http.ResponseWriter, flusher http.Flusher) bool {
	return writeSSE(w, flusher, "state", streamFrame{
		Pool:      s.poolView(),
		Instances: s.instanceViews(),
		Sample:    s.pool.Stats().Recent(),
	})
}

// writeSSE emits one named event, reporting whether the client is still there.
func writeSSE(w http.ResponseWriter, flusher http.Flusher, name string, payload any) bool {
	body, err := json.Marshal(payload)
	if err != nil {
		return false
	}
	if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", name, body); err != nil {
		return false
	}
	flusher.Flush()
	return true
}
