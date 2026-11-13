package appserver

import (
	"os"
	"regexp"

	"ganigeorgiev.com/pocketbase/pocketbase/core"
)

var readerAssetName = regexp.MustCompile(`^[A-Za-z0-9_-]+\.(js|css|woff2|svg)$`)

// ReaderAssetName reports whether name is a bundled reader asset file. Product
// public route policies call it so they admit exactly the assets the reader serves.
func ReaderAssetName(name string) bool { return readerAssetName.MatchString(name) }

// readerFrameSrc is the reader CSP's frame-src directive: none unless the
// application opts into same-origin frames (Policy.ReaderFramesSelf).
func readerFrameSrc(framesSelf bool) string {
	if framesSelf {
		return "frame-src 'self'; "
	}
	return ""
}

// registerReader keeps embedded reader routes narrow. Development mode selects
// its own routes instead; the immutable unpacked application cache is untouched.
func registerReader(e *core.ServeEvent, dir string, framesSelf bool) {
	csp := "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' blob:; media-src 'self' blob:; font-src 'self'; " + readerFrameSrc(framesSelf) + "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
	serve := func(re *core.RequestEvent, file string) error {
		h := re.Response.Header()
		if file == "index.html" {
			h.Set("Cache-Control", "no-store")
		} else {
			h.Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", csp)
		return re.FileFS(os.DirFS(dir), file)
	}
	e.Router.GET("/{$}", func(re *core.RequestEvent) error { return serve(re, "index.html") })
	e.Router.GET("/assets/{name}", func(re *core.RequestEvent) error {
		name := re.Request.PathValue("name")
		if !readerAssetName.MatchString(name) {
			return re.NotFoundError("Not found.", nil)
		}
		return serve(re, "assets/"+name)
	})
}
