// The read path — the actual design driver. Agents hit /api/logs with curl
// one-liners and get grep-friendly text; /api/query takes raw SELECT for the
// investigations the filter params can't express; /api/tail streams via SSE.
//
// One global READ_TOKEN spans all sources by design (single tenant, cross-app
// debugging in one command). The web UI reaches the same API with a broker
// id_token from auth.gawaak.ovh instead.
package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// readAuth admits either the global READ_TOKEN or a verified broker id_token
// (the web UI's path). ?token= is accepted for callers that can't set headers.
func (s *server) readAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if tok == "" {
			tok = r.URL.Query().Get("token")
		}
		if tok == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if s.readToken != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(s.readToken)) == 1 {
			next(w, r)
			return
		}
		// Two dots = shaped like a JWT; try the broker. EmailVerified matters:
		// the rule is "this mailbox", not "anyone who can claim this string".
		// Rejections are logged with their reason — a silent 401 here sends
		// the web UI into a sign-in loop nobody can debug from the outside.
		if strings.Count(tok, ".") == 2 && s.verifier != nil {
			c, err := s.verifier.Verify(r.Context(), tok)
			switch {
			case err != nil:
				log.Printf("read auth: broker token rejected: %v", err)
			case !c.EmailVerified:
				log.Printf("read auth: %s unverified", c.Email)
			case len(s.allowed) > 0 && !s.allowed[strings.ToLower(strings.TrimSpace(c.Email))]:
				log.Printf("read auth: %s not in ALLOWED_EMAILS", c.Email)
			default:
				next(w, r)
				return
			}
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}
}

var durRe = regexp.MustCompile(`^(\d+)([smhd])$`)

// parseWhen accepts durations-ago (30m, 2h, 3d), RFC3339, unix seconds or
// unix milliseconds, and returns milliseconds.
func parseWhen(s string, now time.Time) (int64, error) {
	if m := durRe.FindStringSubmatch(s); m != nil {
		n, _ := strconv.ParseInt(m[1], 10, 64)
		unit := map[string]time.Duration{"s": time.Second, "m": time.Minute, "h": time.Hour, "d": 24 * time.Hour}[m[2]]
		return now.Add(-time.Duration(n) * unit).UnixMilli(), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UnixMilli(), nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		if n >= 1e12 {
			return n, nil // already ms
		}
		return n * 1000, nil // seconds
	}
	return 0, fmt.Errorf("bad time %q (want 30m/2h/3d, RFC3339, or unix)", s)
}

func (s *server) parseLogsQuery(r *http.Request) (logsQuery, error) {
	q := r.URL.Query()
	lq := logsQuery{
		source: q.Get("source"),
		q:      q.Get("q"),
		meta:   map[string]string{},
	}
	if v := q.Get("level"); v != "" {
		lq.minLevel = parseLevel(v)
	}
	now := time.Now()
	var err error
	if v := q.Get("since"); v != "" {
		if lq.since, err = parseWhen(v, now); err != nil {
			return lq, err
		}
	}
	if v := q.Get("before"); v != "" {
		if lq.before, err = parseWhen(v, now); err != nil {
			return lq, err
		}
	}
	if v := q.Get("limit"); v != "" {
		if lq.limit, err = strconv.Atoi(v); err != nil {
			return lq, fmt.Errorf("bad limit %q", v)
		}
	}
	for k, vs := range q {
		if key, ok := strings.CutPrefix(k, "meta."); ok && len(vs) > 0 {
			lq.meta[key] = vs[0]
		}
	}
	return lq, nil
}

// jsonEntryOut is the JSON read shape; text stays the default because the
// consumers are grep and agent eyeballs, not programs.
type jsonEntryOut struct {
	Ts       int64           `json:"ts"`
	Time     string          `json:"time"`
	ClientTs *int64          `json:"clientTs,omitempty"`
	Source   string          `json:"source"`
	Level    string          `json:"level"`
	Msg      string          `json:"msg"`
	Meta     json.RawMessage `json:"meta,omitempty"`
}

func toJSONOut(e entry) jsonEntryOut {
	out := jsonEntryOut{
		Ts:       e.ts,
		Time:     time.UnixMilli(e.ts).UTC().Format("2006-01-02T15:04:05.000Z"),
		ClientTs: e.clientTS,
		Source:   e.source,
		Level:    levelName(e.level),
		Msg:      e.msg,
	}
	if e.meta != "" {
		out.Meta = json.RawMessage(e.meta)
	}
	return out
}

func (s *server) handleLogs(w http.ResponseWriter, r *http.Request) {
	lq, err := s.parseLogsQuery(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	entries, err := s.store.query(ctx, lq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		out := make([]jsonEntryOut, 0, len(entries))
		for _, e := range entries {
			out = append(out, toJSONOut(e))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	for _, e := range entries {
		fmt.Fprintln(w, textLine(e))
	}
}

func (s *server) handleSources(w http.ResponseWriter, _ *http.Request) {
	stats, err := s.store.stats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// --- raw SQL ---

var selectRe = regexp.MustCompile(`(?is)^\s*(select|with)\b`)

// handleQuery runs one SELECT against the query_only read pool: 2s statement
// timeout, hard 1000-row cap. query_only means even a statement that slips
// past the SELECT check cannot write; the single-table schema means there is
// nothing else to leak.
func (s *server) handleQuery(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, maxBody))
	stmt := strings.TrimSpace(string(body))
	for strings.HasSuffix(stmt, ";") {
		stmt = strings.TrimSpace(strings.TrimSuffix(stmt, ";"))
	}
	if !selectRe.MatchString(stmt) {
		http.Error(w, "SELECT statements only", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	rows, err := s.store.rdb.QueryContext(ctx, stmt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var out [][]any
	for rows.Next() && len(out) < 1000 {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for i, v := range vals {
			if b, ok := v.([]byte); ok {
				vals[i] = string(b)
			}
		}
		out = append(out, vals)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"columns": cols, "rows": out})
		return
	}
	// TSV: header then rows — cut/awk/column-friendly.
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, strings.Join(cols, "\t"))
	for _, row := range out {
		cells := make([]string, len(row))
		for i, v := range row {
			if v != nil {
				cells[i] = strings.ReplaceAll(fmt.Sprint(v), "\t", " ")
			}
		}
		fmt.Fprintln(w, strings.Join(cells, "\t"))
	}
}

// --- live tail (SSE) ---

type hub struct {
	mu   sync.Mutex
	subs map[*sub]struct{}
}

type sub struct {
	ch       chan entry
	source   string
	minLevel int
}

func newHub() *hub { return &hub{subs: map[*sub]struct{}{}} }

// publish never blocks ingest: a slow tail consumer just misses lines, which
// is what "tail" means.
func (h *hub) publish(e entry) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.subs {
		if s.source != "" && s.source != e.source {
			continue
		}
		if e.level < s.minLevel {
			continue
		}
		select {
		case s.ch <- e:
		default:
		}
	}
}

func (h *hub) subscribe(source string, minLevel int) *sub {
	s := &sub{ch: make(chan entry, 64), source: source, minLevel: minLevel}
	h.mu.Lock()
	h.subs[s] = struct{}{}
	h.mu.Unlock()
	return s
}

func (h *hub) unsubscribe(s *sub) {
	h.mu.Lock()
	delete(h.subs, s)
	h.mu.Unlock()
}

func (s *server) handleTail(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	minLevel := 0
	if v := r.URL.Query().Get("level"); v != "" {
		minLevel = parseLevel(v)
	}
	sb := s.hub.subscribe(r.URL.Query().Get("source"), minLevel)
	defer s.hub.unsubscribe(sb)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	fmt.Fprintf(w, ": connected\n\n")
	fl.Flush()

	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			fmt.Fprintf(w, ": ping\n\n")
			fl.Flush()
		case e := <-sb.ch:
			fmt.Fprintf(w, "data: %s\n\n", textLine(e))
			fl.Flush()
		}
	}
}

// handleUIDiag is an unauthenticated, log-only beacon for the web UI's
// sign-in failure paths — the UI runs on phones with no devtools attached,
// so the gate posts what it saw and the reason lands in the container log.
// Hard-capped: 512-byte body, shared rate bucket, never touches the DB.
func (s *server) handleUIDiag(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 512))
	if s.allow("_uidiag", time.Now()) {
		log.Printf("uidiag: %s | ua=%q", strings.ReplaceAll(string(body), "\n", " "), r.UserAgent())
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- admin ---

// handleAdmin exposes counters at an unguessable path (ADMIN_PATH env) — the
// path is the secret, same pattern as plandrop's admin.
func (s *server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if s.adminPath == "" || subtle.ConstantTimeCompare([]byte(r.PathValue("key")), []byte(s.adminPath)) != 1 {
		http.NotFound(w, r)
		return
	}
	stats, err := s.store.stats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	size, _ := s.store.sizeBytes()
	drops := map[string]int64{}
	s.rlMu.Lock()
	for name, b := range s.rl {
		if b.drops > 0 {
			drops[name] = b.drops
		}
	}
	s.rlMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"uptimeSec":    int64(time.Since(s.start).Seconds()),
		"dbSizeBytes":  size,
		"dbMaxBytes":   s.store.maxBytes,
		"sources":      stats,
		"rateDrops":    drops,
		"escalations":  s.esc.sentCounts(),
		"configSource": len(s.config()),
	})
}
