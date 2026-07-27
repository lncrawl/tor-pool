package server

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// dashboard is the built Vite output.
//
// A placeholder index.html is committed so `go build` works without running
// npm; the Docker build overwrites the directory with the real bundle. The
// `all:` prefix keeps Vite's dotted asset names from being skipped.
//
//go:embed all:dist
var dashboard embed.FS

// assetCacheControl is applied to hashed asset filenames only.
//
// Vite fingerprints every asset, so those are safe to cache indefinitely, while
// index.html must never be cached or a redeploy keeps serving the old bundle.
const assetCacheControl = "public, max-age=31536000, immutable"

// mountDashboard serves the embedded dashboard at the root.
func (s *Server) mountDashboard(mux *http.ServeMux) {
	root, err := fs.Sub(dashboard, "dist")
	if err != nil {
		s.log.Error("dashboard assets unavailable", "error", err)
		return
	}
	files := http.FileServerFS(root)

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		// An unmatched API route must 404, not fall through to the SPA. Handing
		// a client HTML with a 200 for a mistyped endpoint is far harder to
		// diagnose than a plain not-found.
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}

		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}

		// Anything that is not a real asset falls back to index.html, so a
		// deep link keeps working. Without this the API would answer a
		// bookmarked dashboard URL with a 404.
		if _, err := fs.Stat(root, path); err != nil {
			r = r.Clone(r.Context())
			r.URL.Path = "/"
			w.Header().Set("Cache-Control", "no-cache")
			files.ServeHTTP(w, r)
			return
		}

		if strings.HasPrefix(path, "assets/") {
			w.Header().Set("Cache-Control", assetCacheControl)
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}
