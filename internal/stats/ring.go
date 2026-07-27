// Package stats keeps rolling counters and a bounded event log for the pool.
//
// Everything here lives in memory and is lost on restart. That is a deliberate
// trade for now: the dashboard's value is in what is happening, and adding
// persistence later is contained behind this package.
package stats

import (
	"sync"
	"time"
)

// Sample is one bucket of activity.
type Sample struct {
	At        time.Time `json:"at"`
	Requests  int64     `json:"requests"`
	Failures  int64     `json:"failures"`
	BytesUp   int64     `json:"bytes_up"`
	BytesDown int64     `json:"bytes_down"`
	// Routable is the number of instances able to take traffic in this bucket.
	Routable int `json:"routable"`
	// LatencyP50 and LatencyP95 are connect latencies in milliseconds.
	LatencyP50 float64 `json:"latency_p50_ms"`
	LatencyP95 float64 `json:"latency_p95_ms"`
}

// ring is a fixed-size circular buffer of time buckets.
//
// A ring rather than an append-only slice so memory is bounded by the retention
// window instead of by uptime.
type ring struct {
	buckets    []bucket
	resolution time.Duration
	// head is the index of the newest bucket.
	head  int
	start time.Time
}

// bucket accumulates one resolution-sized slice of time.
type bucket struct {
	at        time.Time
	requests  int64
	failures  int64
	bytesUp   int64
	bytesDown int64
	routable  int
	// latencies holds connect times in milliseconds for this bucket. Kept raw
	// so percentiles are exact within the bucket rather than an average of
	// averages.
	latencies []float64
}

func (b *bucket) reset(at time.Time) {
	*b = bucket{at: at, latencies: b.latencies[:0]}
}

func newRing(resolution, window time.Duration) *ring {
	count := max(int(window/resolution), 1)
	r := &ring{
		buckets:    make([]bucket, count),
		resolution: resolution,
	}
	return r
}

// advance rolls the ring forward so the newest bucket covers now, and returns
// it.
func (r *ring) advance(now time.Time) *bucket {
	slot := now.Truncate(r.resolution)

	if r.start.IsZero() {
		r.start = slot
		r.buckets[r.head].reset(slot)
		return &r.buckets[r.head]
	}

	steps := int(slot.Sub(r.buckets[r.head].at) / r.resolution)
	if steps <= 0 {
		return &r.buckets[r.head]
	}

	// A long idle gap must not be walked bucket by bucket.
	if steps >= len(r.buckets) {
		for i := range r.buckets {
			r.buckets[i].reset(time.Time{})
		}
		r.head = 0
		r.buckets[0].reset(slot)
		return &r.buckets[0]
	}

	for range steps {
		r.head = (r.head + 1) % len(r.buckets)
		r.buckets[r.head].reset(slot)
	}
	return &r.buckets[r.head]
}

// series returns the buckets oldest-first, skipping never-filled slots.
func (r *ring) series() []Sample {
	out := make([]Sample, 0, len(r.buckets))
	for i := 1; i <= len(r.buckets); i++ {
		b := &r.buckets[(r.head+i)%len(r.buckets)]
		if b.at.IsZero() {
			continue
		}
		p50, p95 := percentiles(b.latencies)
		out = append(out, Sample{
			At:         b.at,
			Requests:   b.requests,
			Failures:   b.failures,
			BytesUp:    b.bytesUp,
			BytesDown:  b.bytesDown,
			Routable:   b.routable,
			LatencyP50: p50,
			LatencyP95: p95,
		})
	}
	return out
}

// percentiles returns the p50 and p95 of a bucket's latencies.
//
// The slice is sorted in place, which is safe because it is only read while the
// collector's lock is held.
func percentiles(values []float64) (p50, p95 float64) {
	if len(values) == 0 {
		return 0, 0
	}
	sortFloats(values)
	return quantile(values, 0.50), quantile(values, 0.95)
}

func quantile(sorted []float64, q float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(q * float64(len(sorted)))
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// sortFloats is an insertion sort: buckets hold at most a second or a minute of
// samples, where this beats the overhead of sort.Slice's reflection.
func sortFloats(v []float64) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j-1] > v[j]; j-- {
			v[j-1], v[j] = v[j], v[j-1]
		}
	}
}

// Collector accumulates pool-wide and per-instance activity.
type Collector struct {
	mu sync.Mutex

	fine   *ring // high resolution, short window
	coarse *ring // low resolution, long window

	totals    Totals
	instances map[int]*InstanceTotals
}

// Totals are lifetime counters for the whole pool.
type Totals struct {
	Requests  int64 `json:"requests"`
	Failures  int64 `json:"failures"`
	BytesUp   int64 `json:"bytes_up"`
	BytesDown int64 `json:"bytes_down"`
}

// InstanceTotals are lifetime counters for one instance.
type InstanceTotals struct {
	Requests  int64   `json:"requests"`
	Failures  int64   `json:"failures"`
	BytesUp   int64   `json:"bytes_up"`
	BytesDown int64   `json:"bytes_down"`
	LatencyMS float64 `json:"latency_ms"`
	// latencySamples backs the running mean in LatencyMS.
	latencySamples int64
}

// NewCollector builds a collector with the given fine resolution and window.
//
// The coarse ring keeps a longer history at minute resolution so the dashboard
// can zoom out without the memory cost of a second-resolution ring covering
// hours.
func NewCollector(resolution, window time.Duration) *Collector {
	return &Collector{
		fine:      newRing(resolution, window),
		coarse:    newRing(time.Minute, 6*time.Hour),
		instances: make(map[int]*InstanceTotals),
	}
}

// RecordRequest adds one completed connection.
func (c *Collector) RecordRequest(instance int, bytesUp, bytesDown int64, latency time.Duration, failed bool) {
	now := time.Now()
	ms := float64(latency.Microseconds()) / 1000

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, r := range []*ring{c.fine, c.coarse} {
		b := r.advance(now)
		b.requests++
		b.bytesUp += bytesUp
		b.bytesDown += bytesDown
		if failed {
			b.failures++
		}
		if latency > 0 {
			b.latencies = append(b.latencies, ms)
		}
	}

	c.totals.Requests++
	c.totals.BytesUp += bytesUp
	c.totals.BytesDown += bytesDown
	if failed {
		c.totals.Failures++
	}

	it := c.instanceLocked(instance)
	it.Requests++
	it.BytesUp += bytesUp
	it.BytesDown += bytesDown
	if failed {
		it.Failures++
	}
	if latency > 0 {
		// Running mean, so per-instance latency costs no memory.
		it.latencySamples++
		it.LatencyMS += (ms - it.LatencyMS) / float64(it.latencySamples)
	}
}

// RecordRoutable notes how many instances were routable at this moment.
func (c *Collector) RecordRoutable(n int) {
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()
	for _, r := range []*ring{c.fine, c.coarse} {
		r.advance(now).routable = n
	}
}

// Forget drops an instance's counters when it is retired.
func (c *Collector) Forget(instance int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.instances, instance)
}

func (c *Collector) instanceLocked(instance int) *InstanceTotals {
	it, ok := c.instances[instance]
	if !ok {
		it = &InstanceTotals{}
		c.instances[instance] = it
	}
	return it
}

// Totals returns the lifetime pool counters.
func (c *Collector) Totals() Totals {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.totals
}

// Instance returns one instance's lifetime counters.
func (c *Collector) Instance(instance int) InstanceTotals {
	c.mu.Lock()
	defer c.mu.Unlock()
	if it, ok := c.instances[instance]; ok {
		return *it
	}
	return InstanceTotals{}
}

// History returns the recent time series. Fine resolution by default; coarse
// when a longer view is asked for.
func (c *Collector) History(coarse bool) []Sample {
	c.mu.Lock()
	defer c.mu.Unlock()
	if coarse {
		return c.coarse.series()
	}
	return c.fine.series()
}

// Recent returns the newest fine-resolution sample, for live updates.
func (c *Collector) Recent() Sample {
	c.mu.Lock()
	defer c.mu.Unlock()

	series := c.fine.series()
	if len(series) == 0 {
		return Sample{At: time.Now()}
	}
	return series[len(series)-1]
}
