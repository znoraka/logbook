// Ingest: POST /log/<source>. The contract with clients is fire-and-forget —
// they swallow errors and never retry on user paths — so this side is
// symmetrically forgiving: unknown levels become info, oversize payloads are
// truncated rather than rejected, and non-JSON bodies are stored verbatim.
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	maxBody = 64 << 10 // whole request
	maxMsg  = 4 << 10  // per message
	maxMeta = 8 << 10  // per metadata blob, post-compaction
)

// jsonEntry is the permissive wire shape: {level, msg, meta, ts}. Level may be
// a string or a number; msg/message are synonyms; ts is client milliseconds.
type jsonEntry struct {
	Level   any             `json:"level"`
	Msg     string          `json:"msg"`
	Message string          `json:"message"`
	Meta    json.RawMessage `json:"meta"`
	Ts      int64           `json:"ts"`
}

func (s *server) handleLog(w http.ResponseWriter, r *http.Request) {
	source := r.PathValue("source")
	sc, ok := s.config()[source]
	if !ok {
		http.Error(w, "unknown source", http.StatusNotFound)
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		token = r.URL.Query().Get("token")
	}
	if sc.Token == "" || token != sc.Token {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	now := time.Now()
	if !s.allow(source, now) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, maxBody))
	entries := parseEntries(source, body, now)
	if len(entries) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err := s.store.insert(entries); err != nil {
		log.Printf("insert %s: %v", source, err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	for _, e := range entries {
		s.hub.publish(e)
		if sc.Escalate != nil && e.level >= parseLevel(sc.Escalate.MinLevel) {
			s.esc.note(source, sc.Escalate, e, s.postNotify)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// parseEntries turns a request body into rows: a JSON object, a JSON array
// (the batching clients), or plain text. Parse failures fall back to plain
// text — a malformed log line is still a log line.
func parseEntries(source string, body []byte, now time.Time) []entry {
	b := bytes.TrimSpace(body)
	if len(b) == 0 {
		return nil
	}
	switch b[0] {
	case '{':
		var je jsonEntry
		if json.Unmarshal(b, &je) == nil {
			if e, ok := fromJSON(source, je, now); ok {
				return []entry{e}
			}
			return nil
		}
	case '[':
		var batch []jsonEntry
		if json.Unmarshal(b, &batch) == nil {
			var out []entry
			for _, je := range batch {
				if e, ok := fromJSON(source, je, now); ok {
					out = append(out, e)
				}
			}
			return out
		}
	}
	return []entry{{
		ts:     now.UnixMilli(),
		source: source,
		level:  1,
		msg:    truncate(string(b), maxMsg),
	}}
}

func fromJSON(source string, je jsonEntry, now time.Time) (entry, bool) {
	msg := je.Msg
	if msg == "" {
		msg = je.Message
	}
	if msg == "" && len(je.Meta) == 0 {
		return entry{}, false
	}
	e := entry{
		ts:     now.UnixMilli(),
		source: source,
		level:  toLevel(je.Level),
		msg:    truncate(msg, maxMsg),
	}
	if je.Ts > 0 {
		// Client clocks drift and webviews replay queued batches; keep the
		// claim but clamp it so one bad clock can't scatter rows across time.
		cts := min(max(je.Ts, now.UnixMilli()-day24h), now.UnixMilli()+day24h)
		e.clientTS = &cts
	}
	if len(je.Meta) > 0 && string(je.Meta) != "null" {
		var buf bytes.Buffer
		if json.Compact(&buf, je.Meta) == nil {
			if buf.Len() <= maxMeta {
				e.meta = buf.String()
			} else {
				e.meta = `{"logbook":"meta truncated"}`
			}
		}
	}
	return e, true
}

const day24h = int64(24 * time.Hour / time.Millisecond)

// toLevel accepts "warn", 2, or 2.0 — clients in three languages get to be
// sloppy in three ways.
func toLevel(v any) int {
	switch t := v.(type) {
	case string:
		return parseLevel(t)
	case float64:
		n := int(t)
		if n >= 0 && n <= 3 {
			return n
		}
	}
	return 1
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
