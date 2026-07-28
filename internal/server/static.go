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

	// The assets are served without a credential on purpose: an unauthenticated
	// browser has to be able to load the app in order to render its own login
	// screen. Only the bundle is public — every /api/ call it makes is not.
	//
	// Unmatched /api/ paths never reach here: the route table registers the whole
	// subtree, so a mistyped endpoint is authenticated and then 404s instead of
	// being answered with HTML and a 200.
	// Registered without a method so it can coexist with the route table's /api/
	// subtree pattern: ServeMux rejects a method-specific general pattern
	// alongside a method-less specific one. That also means every method on an
	// unmatched /api/ path is authenticated before it answers, rather than a POST
	// getting a 405 while a GET gets a 401.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
