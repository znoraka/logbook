// logbook — one log sink for every app. Apps POST lines to /log/<source> with
// a per-source bearer token; agents read them back through /api/logs, /api/tail
// (SSE) and /api/query (raw SELECT). One Go binary, one SQLite file. The read
// side is deliberately all-seeing: every source is one personal app, and
// cross-app debugging in a single query is the point.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/znoraka/auth/verify"
)

// sourceCfg is one entry of /data/sources.json. The file is the whole
// onboarding story: add a source with a token, redeploy nothing — it is
// hot-reloaded.
type sourceCfg struct {
	Token         string       `json:"token"`
	RetentionDays int          `json:"retentionDays"` // 0 → default 14
	Escalate      *escalateCfg `json:"escalate"`
}

// escalateCfg forwards error-and-up entries to notify-relay, which owns the
// Signal delivery. logbook never talks to Signal directly.
type escalateCfg struct {
	MinLevel     string `json:"minLevel"`
	NotifySource string `json:"notifySource"`
	Token        string `json:"token"` // empty → NOTIFY_TOKEN env
}

type config map[string]sourceCfg

const defaultRetentionDays = 14

type server struct {
	cfg atomic.Value // config

	store *store

	readToken string
	adminPath string

	notifyURL   string
	notifyToken string

	verifier *verify.Verifier
	allowed  map[string]bool // lowercased emails; empty → any verified broker account

	hub *hub
	esc *escalator

	// Ingest rate limiting: refillPerSec sustained with burst capacity,
	// per source. Fields rather than consts so tests can shrink them.
	rlMu         sync.Mutex
	rl           map[string]*bucket
	refillPerSec float64
	burst        float64

	start time.Time
}

// bucket is a token bucket plus the per-source drop counter the plan asks for.
type bucket struct {
	tokens float64
	last   time.Time
	drops  int64
}

// allow spends one token from the source's bucket, refilling first.
func (s *server) allow(source string, now time.Time) bool {
	s.rlMu.Lock()
	defer s.rlMu.Unlock()
	b, ok := s.rl[source]
	if !ok {
		b = &bucket{tokens: s.burst, last: now}
		s.rl[source] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * s.refillPerSec
	if b.tokens > s.burst {
		b.tokens = s.burst
	}
	b.last = now
	if b.tokens < 1 {
		b.drops++
		return false
	}
	b.tokens--
	return true
}

func (s *server) config() config {
	c, _ := s.cfg.Load().(config)
	return c
}

// loadConfig reads the sources file, falling back to SOURCES_JSON for local
// runs. A missing file is not fatal: the server still serves reads, and every
// ingest just 404s until the mount appears.
func loadConfig(path string) (config, error) {
	if b, err := os.ReadFile(path); err == nil {
		var c config
		return c, json.Unmarshal(b, &c)
	}
	if j := os.Getenv("SOURCES_JSON"); j != "" {
		var c config
		return c, json.Unmarshal([]byte(j), &c)
	}
	return nil, fmt.Errorf("no config: %s missing and SOURCES_JSON unset", path)
}

// watchConfig hot-reloads the sources file on mtime change. Polling every 10s
// is plenty: token rotation is a human act, not a hot path.
func (s *server) watchConfig(path string) {
	var last time.Time
	if fi, err := os.Stat(path); err == nil {
		last = fi.ModTime()
	}
	for range time.Tick(10 * time.Second) {
		fi, err := os.Stat(path)
		if err != nil || fi.ModTime().Equal(last) {
			continue
		}
		last = fi.ModTime()
		c, err := loadConfig(path)
		if err != nil {
			log.Printf("config reload: %v (keeping previous)", err)
			continue
		}
		s.cfg.Store(c)
		log.Printf("config reloaded: %d sources", len(c))
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func (s *server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /log/{source}", s.handleLog)
	mux.HandleFunc("GET /api/logs", s.readAuth(s.handleLogs))
	mux.HandleFunc("GET /api/tail", s.readAuth(s.handleTail))
	mux.HandleFunc("POST /api/query", s.readAuth(s.handleQuery))
	mux.HandleFunc("GET /api/sources", s.readAuth(s.handleSources))
	mux.HandleFunc("POST /uidiag", s.handleUIDiag)
	mux.HandleFunc("GET /admin/{key}", s.handleAdmin)
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	mux.HandleFunc("GET /{$}", s.handleIndex)
	return mux
}

func main() {
	dbPath := envOr("DB_PATH", "/data/logbook.db")
	cfgPath := envOr("CONFIG", "/data/sources.json")

	st, err := openStore(dbPath, int64(atoiOr(envOr("DB_MAX_MB", "512"), 512))<<20)
	if err != nil {
		log.Fatalf("open %s: %v", dbPath, err)
	}

	baseURL := envOr("BASE_URL", "https://logs.gawaak.ovh")
	s := &server{
		store:        st,
		readToken:    os.Getenv("READ_TOKEN"),
		adminPath:    os.Getenv("ADMIN_PATH"),
		notifyURL:    strings.TrimSuffix(envOr("NOTIFY_URL", "https://notify.gawaak.ovh"), "/"),
		notifyToken:  os.Getenv("NOTIFY_TOKEN"),
		verifier:     verify.New(envOr("AUTH_ISSUER", "https://auth.gawaak.ovh"), baseURL),
		allowed:      map[string]bool{},
		hub:          newHub(),
		esc:          newEscalator(5 * time.Minute),
		rl:           map[string]*bucket{},
		refillPerSec: 1, // 60/min sustained
		burst:        300,
		start:        time.Now(),
	}
	for _, e := range strings.Split(os.Getenv("ALLOWED_EMAILS"), ",") {
		if e = strings.ToLower(strings.TrimSpace(e)); e != "" {
			s.allowed[e] = true
		}
	}
	if s.readToken == "" {
		log.Printf("warning: READ_TOKEN unset — read API only reachable with broker tokens")
	}

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		log.Printf("warning: %v — ingest disabled until config appears", err)
		cfg = config{}
	}
	s.cfg.Store(cfg)
	go s.watchConfig(cfgPath)

	go func() {
		for {
			if err := s.store.sweep(s.config()); err != nil {
				log.Printf("sweep: %v", err)
			}
			time.Sleep(time.Hour)
		}
	}()

	addr := envOr("LISTEN", ":8080")
	log.Printf("logbook listening on %s, %d sources, db %s", addr, len(cfg), dbPath)
	log.Fatal(http.ListenAndServe(addr, s.routes()))
}

func atoiOr(s string, def int) int {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil || n <= 0 {
		return def
	}
	return n
}
