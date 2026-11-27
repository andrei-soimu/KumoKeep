// Package web serves the SvelteKit web app embedded in the binary.
//
// `make web` builds web/ and copies the output into dist/. Without a build,
// a placeholder page is served.
package web

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var dist embed.FS

// The SvelteKit build carries a <meta> CSP with hashes for its inline
// bootstrap script (csp option in web/vite.config.ts). The header adds the
// directives a <meta> CSP can't express.
const htmlCSP = "frame-ancestors 'none'; object-src 'none'; base-uri 'none'"

// fallback is the SPA entry page written by adapter-static (web/vite.config.ts).
const fallback = "200.html"

const placeholder = `<!doctype html><meta charset="utf-8"><title>KumoKeep</title>
<p>The KumoKeep web app is not built yet. Run <code>make web</code>, then rebuild the server.</p>`

func Handler() http.Handler {
	files, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	_, statErr := fs.Stat(files, fallback)
	built := statErr == nil
	fileServer := http.FileServerFS(files)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Security-Policy", htmlCSP)
		if !built {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(placeholder))
			return
		}

		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if strings.HasPrefix(name, "_app/immutable/") {
			// Content-hashed filenames: safe to cache forever.
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}

		if name != "" && name != fallback {
			if st, err := fs.Stat(files, name); err == nil && !st.IsDir() {
				fileServer.ServeHTTP(w, r)
				return
			}
			if path.Ext(name) != "" {
				http.NotFound(w, r) // a missing asset, not an app route
				return
			}
		}
		// SPA fallback: client-side routes are handled by the app.
		http.ServeFileFS(w, r, files, fallback)
	})
}
