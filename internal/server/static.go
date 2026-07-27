package server

import (
	"net/http"
)

// mountDashboard serves the embedded dashboard at the root.
//
// The built assets are added alongside the dashboard itself; until then the
// root explains where the API is rather than 404ing, so a browser pointed at
// the port gets something useful.
func (s *Server) mountDashboard(mux *http.ServeMux) {
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(
			"tor-pool\n\n" +
				"The dashboard is not built into this binary.\n" +
				"API:     /api/pool, /api/instances, /api/sessions, /api/events\n" +
				"Stream:  /api/stream\n" +
				"Metrics: /metrics\n" +
				"Health:  /health\n"))
	})
}
