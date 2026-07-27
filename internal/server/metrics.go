package server

import (
	"fmt"
	"net/http"
	"strings"
)

// handleMetrics writes the Prometheus text exposition format.
//
// Hand-written rather than pulling in the client library: the metric set is
// small and fixed, and the module has no third-party dependencies, which is
// part of why the image is as small as it is.
func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	var b strings.Builder

	instances := s.instanceViews()
	view := s.poolView()

	metric(&b, "torpool_instances_total", "gauge",
		"Number of tor instances in the pool.")
	fmt.Fprintf(&b, "torpool_instances_total %d\n", view.Size)

	metric(&b, "torpool_instances_routable", "gauge",
		"Instances currently able to take traffic.")
	fmt.Fprintf(&b, "torpool_instances_routable %d\n", view.Routable)

	metric(&b, "torpool_sessions_active", "gauge",
		"Sessions currently pinned to an instance.")
	fmt.Fprintf(&b, "torpool_sessions_active %d\n", view.Sessions)

	metric(&b, "torpool_requests_total", "counter",
		"Connections proxied since start.")
	fmt.Fprintf(&b, "torpool_requests_total %d\n", view.Totals.Requests)

	metric(&b, "torpool_failures_total", "counter",
		"Connections that failed since start.")
	fmt.Fprintf(&b, "torpool_failures_total %d\n", view.Totals.Failures)

	metric(&b, "torpool_bytes_total", "counter",
		"Bytes relayed since start, by direction.")
	fmt.Fprintf(&b, "torpool_bytes_total{direction=\"up\"} %d\n", view.Totals.BytesUp)
	fmt.Fprintf(&b, "torpool_bytes_total{direction=\"down\"} %d\n", view.Totals.BytesDown)

	metric(&b, "torpool_instance_state", "gauge",
		"1 for the state an instance is currently in, 0 otherwise.")
	for i := range instances {
		inst := &instances[i]
		// One series per state rather than an opaque number, so a query can ask
		// "how many are quarantined" without decoding an enum.
		for _, state := range []string{"starting", "healthy", "degraded", "probation", "quarantined", "remediating"} {
			value := 0
			if string(inst.Health.State) == state {
				value = 1
			}
			fmt.Fprintf(&b, "torpool_instance_state{instance=\"%d\",state=\"%s\"} %d\n",
				inst.ID, state, value)
		}
	}

	metric(&b, "torpool_instance_bootstrap_percent", "gauge",
		"Tor bootstrap progress per instance.")
	for i := range instances {
		inst := &instances[i]
		fmt.Fprintf(&b, "torpool_instance_bootstrap_percent{instance=\"%d\"} %d\n",
			inst.ID, inst.Bootstrap)
	}

	metric(&b, "torpool_instance_sessions", "gauge",
		"Sessions pinned to each instance.")
	for i := range instances {
		inst := &instances[i]
		fmt.Fprintf(&b, "torpool_instance_sessions{instance=\"%d\"} %d\n", inst.ID, inst.Sessions)
	}

	metric(&b, "torpool_instance_requests_total", "counter",
		"Connections proxied per instance.")
	for i := range instances {
		inst := &instances[i]
		fmt.Fprintf(&b, "torpool_instance_requests_total{instance=\"%d\"} %d\n",
			inst.ID, inst.Totals.Requests)
	}

	metric(&b, "torpool_instance_failures_total", "counter",
		"Failures per instance, by which side observed them.")
	for i := range instances {
		inst := &instances[i]
		fmt.Fprintf(&b, "torpool_instance_failures_total{instance=\"%d\",source=\"transport\"} %d\n",
			inst.ID, inst.Health.TransportFailures)
		fmt.Fprintf(&b, "torpool_instance_failures_total{instance=\"%d\",source=\"client\"} %d\n",
			inst.ID, inst.Health.ClientFailures)
	}

	metric(&b, "torpool_instance_bytes_total", "counter",
		"Bytes relayed per instance, by direction.")
	for i := range instances {
		inst := &instances[i]
		fmt.Fprintf(&b, "torpool_instance_bytes_total{instance=\"%d\",direction=\"up\"} %d\n",
			inst.ID, inst.Totals.BytesUp)
		fmt.Fprintf(&b, "torpool_instance_bytes_total{instance=\"%d\",direction=\"down\"} %d\n",
			inst.ID, inst.Totals.BytesDown)
	}

	metric(&b, "torpool_instance_connect_latency_ms", "gauge",
		"Mean time to establish a connection through each instance.")
	for i := range instances {
		inst := &instances[i]
		fmt.Fprintf(&b, "torpool_instance_connect_latency_ms{instance=\"%d\"} %.2f\n",
			inst.ID, inst.Totals.LatencyMS)
	}

	metric(&b, "torpool_instance_remediations_total", "counter",
		"Remediations applied per instance.")
	for i := range instances {
		inst := &instances[i]
		fmt.Fprintf(&b, "torpool_instance_remediations_total{instance=\"%d\"} %d\n",
			inst.ID, inst.Health.Remediations)
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}

func metric(b *strings.Builder, name, kind, help string) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, kind)
}
