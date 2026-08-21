package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	tokWrite = "write-token"
	tokRead  = "read-token"
)

func newTestServer(t *testing.T, cfg config) (*server, *httptest.Server) {
	t.Helper()
	st, err := openStore(filepath.Join(t.TempDir(), "test.db"), 512<<20)
	if err != nil {
		t.Fatal(err)
	}
	s := &server{
		store:        st,
		readToken:    tokRead,
		adminPath:    "adm",
		hub:          newHub(),
		esc:          newEscalator(5 * time.Minute),
		rl:           map[string]*bucket{},
		refillPerSec: 1000, // effectively off unless a test shrinks it
		burst:        1000,
		start:        time.Now(),
	}
	if cfg == nil {
		cfg = config{"app": {Token: tokWrite}}
	}
	s.cfg.Store(cfg)
	ts := httptest.NewServer(s.routes())
	t.Cleanup(ts.Close)
	return s, ts
}

func post(t *testing.T, url, token, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func get(t *testing.T, url, token, accept string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var sb strings.Builder
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		sb.WriteString(sc.Text() + "\n")
	}
	return resp.StatusCode, sb.String()
}

func TestIngestPlainText(t *testing.T) {
	_, ts := newTestServer(t, nil)
	if r := post(t, ts.URL+"/log/app", tokWrite, "nightly update ok"); r.StatusCode != 204 {
		t.Fatalf("status %d", r.StatusCode)
	}
	code, body := get(t, ts.URL+"/api/logs", tokRead, "")
	if code != 200 || !strings.Contains(body, "info app nightly update ok") {
		t.Fatalf("code %d body %q", code, body)
	}
}

func TestIngestJSON(t *testing.T) {
	_, ts := newTestServer(t, nil)
	post(t, ts.URL+"/log/app", tokWrite,
		`{"level":"error","msg":"vtt-failed vid=abc","meta":{"status":403,"version":"1.0.24"}}`)
	code, body := get(t, ts.URL+"/api/logs", tokRead, "application/json")
	if code != 200 {
		t.Fatalf("code %d", code)
	}
	var rows []jsonEntryOut
	if err := json.Unmarshal([]byte(body), &rows); err != nil || len(rows) != 1 {
		t.Fatalf("rows %v err %v", rows, err)
	}
	if rows[0].Level != "error" || rows[0].Msg != "vtt-failed vid=abc" {
		t.Fatalf("row %+v", rows[0])
	}
	if !strings.Contains(string(rows[0].Meta), `"status":403`) {
		t.Fatalf("meta %s", rows[0].Meta)
	}
}

func TestIngestBatchAndClientTs(t *testing.T) {
	s, ts := newTestServer(t, nil)
	old := time.Now().Add(-48 * time.Hour).UnixMilli() // clamps to -24h
	post(t, ts.URL+"/log/app", tokWrite,
		fmt.Sprintf(`[{"msg":"a"},{"level":"warn","msg":"b","ts":%d}]`, old))
	entries, err := s.store.query(context.Background(), logsQuery{})
	if err != nil || len(entries) != 2 {
		t.Fatalf("entries %d err %v", len(entries), err)
	}
	b := entries[1]
	if b.level != 2 || b.clientTS == nil {
		t.Fatalf("entry %+v", b)
	}
	if drift := *b.clientTS - time.Now().Add(-24*time.Hour).UnixMilli(); drift < -5000 || drift > 5000 {
		t.Fatalf("clientTS not clamped: drift %d", drift)
	}
}

func TestIngestAuth(t *testing.T) {
	_, ts := newTestServer(t, nil)
	if r := post(t, ts.URL+"/log/app", "wrong", "x"); r.StatusCode != 401 {
		t.Fatalf("want 401, got %d", r.StatusCode)
	}
	if r := post(t, ts.URL+"/log/nope", tokWrite, "x"); r.StatusCode != 404 {
		t.Fatalf("want 404, got %d", r.StatusCode)
	}
}

func TestIngestTruncation(t *testing.T) {
	s, ts := newTestServer(t, nil)
	post(t, ts.URL+"/log/app", tokWrite, strings.Repeat("x", 10000))
	entries, _ := s.store.query(context.Background(), logsQuery{})
	if len(entries) != 1 || len(entries[0].msg) > maxMsg+4 {
		t.Fatalf("msg len %d", len(entries[0].msg))
	}
}

func TestRateLimit(t *testing.T) {
	s, ts := newTestServer(t, nil)
	s.refillPerSec, s.burst = 0.0001, 3
	codes := map[int]int{}
	for range 5 {
		codes[post(t, ts.URL+"/log/app", tokWrite, "x").StatusCode]++
	}
	if codes[204] != 3 || codes[429] != 2 {
		t.Fatalf("codes %v", codes)
	}
	s.rlMu.Lock()
	drops := s.rl["app"].drops
	s.rlMu.Unlock()
	if drops != 2 {
		t.Fatalf("drops %d", drops)
	}
}

func TestReadFilters(t *testing.T) {
	_, ts := newTestServer(t, config{
		"a": {Token: tokWrite}, "b": {Token: tokWrite},
	})
	post(t, ts.URL+"/log/a", tokWrite, `{"level":"error","msg":"boom","meta":{"status":403}}`)
	post(t, ts.URL+"/log/a", tokWrite, `{"level":"debug","msg":"quiet"}`)
	post(t, ts.URL+"/log/b", tokWrite, `{"level":"warn","msg":"boom other"}`)

	check := func(query string, want, dontWant string) {
		t.Helper()
		code, body := get(t, ts.URL+"/api/logs?"+query, tokRead, "")
		if code != 200 {
			t.Fatalf("%s: code %d", query, code)
		}
		if want != "" && !strings.Contains(body, want) {
			t.Fatalf("%s: missing %q in %q", query, want, body)
		}
		if dontWant != "" && strings.Contains(body, dontWant) {
			t.Fatalf("%s: unwanted %q in %q", query, dontWant, body)
		}
	}
	check("source=a", "boom", "boom other")
	check("level=warn", "boom other", "quiet")
	check("q=boom", "boom", "quiet")
	check("meta.status=403", "boom", "quiet")
	check("since=1h", "boom", "")
	check("since="+fmt.Sprint(time.Now().Add(time.Hour).UnixMilli()), "", "boom")
	check("limit=1", "boom other", "quiet") // newest only

	if code, _ := get(t, ts.URL+"/api/logs?since=banana", tokRead, ""); code != 400 {
		t.Fatalf("bad since: code %d", code)
	}
}

func TestReadAuth(t *testing.T) {
	_, ts := newTestServer(t, nil)
	if code, _ := get(t, ts.URL+"/api/logs", "", ""); code != 401 {
		t.Fatalf("no token: %d", code)
	}
	if code, _ := get(t, ts.URL+"/api/logs", "wrong", ""); code != 401 {
		t.Fatalf("wrong token: %d", code)
	}
	if code, _ := get(t, ts.URL+"/api/logs?token="+tokRead, "", ""); code != 200 {
		t.Fatalf("query token: %d", code)
	}
}

func TestQueryEndpoint(t *testing.T) {
	_, ts := newTestServer(t, nil)
	post(t, ts.URL+"/log/app", tokWrite, `{"level":"error","msg":"boom"}`)
	post(t, ts.URL+"/log/app", tokWrite, `{"level":"error","msg":"boom"}`)

	req := func(body, accept string) (int, string) {
		r, _ := http.NewRequest("POST", ts.URL+"/api/query", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+tokRead)
		if accept != "" {
			r.Header.Set("Accept", accept)
		}
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var sb strings.Builder
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			sb.WriteString(sc.Text() + "\n")
		}
		return resp.StatusCode, sb.String()
	}

	code, body := req("SELECT msg, count(*) n FROM logs GROUP BY msg;", "")
	if code != 200 || !strings.Contains(body, "boom\t2") {
		t.Fatalf("tsv: code %d body %q", code, body)
	}
	code, body = req("SELECT count(*) n FROM logs", "application/json")
	if code != 200 || !strings.Contains(body, `"rows":[[2]]`) {
		t.Fatalf("json: code %d body %q", code, body)
	}
	if code, _ = req("DELETE FROM logs", ""); code != 400 {
		t.Fatalf("delete: code %d", code)
	}
	// Even a SELECT-shaped statement can't write: query_only on the read pool.
	if code, body = req("WITH x AS (SELECT 1) INSERT INTO logs SELECT * FROM x", ""); code == 200 {
		t.Fatalf("smuggled insert: %q", body)
	}
}

func TestSweeperRetention(t *testing.T) {
	s, _ := newTestServer(t, config{"app": {Token: tokWrite, RetentionDays: 7}})
	old := time.Now().Add(-10 * 24 * time.Hour).UnixMilli()
	fresh := time.Now().UnixMilli()
	s.store.insert([]entry{
		{ts: old, source: "app", level: 1, msg: "old"},
		{ts: fresh, source: "app", level: 1, msg: "fresh"},
		{ts: old, source: "ghost", level: 1, msg: "unknown source, 10d"},
	})
	if err := s.store.sweep(s.config()); err != nil {
		t.Fatal(err)
	}
	entries, _ := s.store.query(context.Background(), logsQuery{})
	if len(entries) != 2 {
		t.Fatalf("want 2 rows (fresh + 10d-old ghost under 14d default), got %d", len(entries))
	}
	for _, e := range entries {
		if e.msg == "old" {
			t.Fatal("expired row survived")
		}
	}
}

func TestSweeperGlobalCap(t *testing.T) {
	s, _ := newTestServer(t, nil)
	var batch []entry
	for i := range 20000 {
		batch = append(batch, entry{
			ts: time.Now().UnixMilli() + int64(i), source: "app", level: 1,
			msg: strings.Repeat("p", 200),
		})
	}
	if err := s.store.insert(batch); err != nil {
		t.Fatal(err)
	}
	before, _ := s.store.sizeBytes()
	s.store.maxBytes = 2 << 20 // 2 MB, well under the ~5 MB inserted
	if err := s.store.sweep(s.config()); err != nil {
		t.Fatal(err)
	}
	after, _ := s.store.sizeBytes()
	if after > s.store.maxBytes {
		t.Fatalf("size %d still above cap (was %d)", after, before)
	}
	var n int
	s.store.rdb.QueryRow("SELECT count(*) FROM logs").Scan(&n)
	if n == 0 || n == 20000 {
		t.Fatalf("trim removed %d of 20000 — expected partial", 20000-n)
	}
}

func TestEscalation(t *testing.T) {
	var mu sync.Mutex
	var got []string
	capture := func(_ *escalateCfg, text string) {
		mu.Lock()
		got = append(got, text)
		mu.Unlock()
	}
	esc := newEscalator(100 * time.Millisecond)
	cfg := &escalateCfg{MinLevel: "error", NotifySource: "adhoc"}
	e := entry{source: "app", level: 3, msg: "boom"}

	esc.note("app", cfg, e, capture)
	esc.note("app", cfg, e, capture) // inside window → suppressed
	esc.note("app", cfg, e, capture)
	time.Sleep(150 * time.Millisecond)
	esc.note("app", cfg, e, capture) // window over → sends with count
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("sends %v", got)
	}
	if !strings.Contains(got[0], "app error: boom") {
		t.Fatalf("first %q", got[0])
	}
	if !strings.Contains(got[1], "(+2 suppressed)") {
		t.Fatalf("second %q", got[1])
	}
}

func TestEscalationWiredToIngest(t *testing.T) {
	var hits atomic.Int64
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hook/adhoc" && r.Header.Get("Authorization") == "Bearer ntok" {
			hits.Add(1)
		}
		w.WriteHeader(202)
	}))
	defer relay.Close()

	s, ts := newTestServer(t, config{"app": {
		Token:    tokWrite,
		Escalate: &escalateCfg{MinLevel: "error", NotifySource: "adhoc"},
	}})
	s.notifyURL, s.notifyToken = relay.URL, "ntok"

	post(t, ts.URL+"/log/app", tokWrite, `{"level":"info","msg":"fine"}`)
	post(t, ts.URL+"/log/app", tokWrite, `{"level":"error","msg":"boom"}`)
	deadline := time.Now().Add(2 * time.Second)
	for hits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if hits.Load() != 1 {
		t.Fatalf("relay hits %d", hits.Load())
	}
}

func TestTailSSE(t *testing.T) {
	_, ts := newTestServer(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", ts.URL+"/api/tail?level=warn&token="+tokRead, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	lines := make(chan string, 10)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()
	// wait for the SSE preamble before publishing
	if l := <-lines; !strings.HasPrefix(l, ": connected") {
		t.Fatalf("preamble %q", l)
	}
	post(t, ts.URL+"/log/app", tokWrite, `{"level":"debug","msg":"filtered out"}`)
	post(t, ts.URL+"/log/app", tokWrite, `{"level":"error","msg":"streamed"}`)
	for {
		select {
		case l := <-lines:
			if strings.Contains(l, "filtered out") {
				t.Fatal("level filter failed")
			}
			if strings.Contains(l, "error app streamed") {
				return // success
			}
		case <-ctx.Done():
			t.Fatal("timed out waiting for SSE line")
		}
	}
}

func TestAdmin(t *testing.T) {
	_, ts := newTestServer(t, nil)
	post(t, ts.URL+"/log/app", tokWrite, "x")
	if code, _ := get(t, ts.URL+"/admin/wrong", "", ""); code != 404 {
		t.Fatalf("wrong key: %d", code)
	}
	code, body := get(t, ts.URL+"/admin/adm", "", "")
	if code != 200 || !strings.Contains(body, `"rows":1`) {
		t.Fatalf("code %d body %q", code, body)
	}
}
