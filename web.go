// The web UI is one embedded page. It is a *viewer over the same read API*
// the agents use: auth.js from auth.gawaak.ovh mints a broker id_token in the
// browser, and every fetch carries it as the bearer token — no session state
// on this side at all.
package main

import (
	_ "embed"
	"net/http"
)

//go:embed index.html
var indexHTML []byte

func (s *server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// no-store: a stale cached page once turned a sign-in bug into an
	// undebuggable loop; the page is tiny, always fetch it fresh.
	w.Header().Set("Cache-Control", "no-store")
	w.Write(indexHTML)
}
