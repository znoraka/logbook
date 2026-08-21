// Escalation: error-and-up entries can be forwarded to notify-relay, which
// owns the Signal side. Throttled to one send per source per window (5 min in
// production) with a suppressed-count carried on the next send, and always in
// a goroutine — an unreachable relay must never slow ingest.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

type escalator struct {
	mu         sync.Mutex
	window     time.Duration
	last       map[string]time.Time
	suppressed map[string]int
	sent       map[string]int64
}

func newEscalator(window time.Duration) *escalator {
	return &escalator{
		window:     window,
		last:       map[string]time.Time{},
		suppressed: map[string]int{},
		sent:       map[string]int64{},
	}
}

type notifyFn func(esc *escalateCfg, text string)

// note either sends now (window elapsed) or counts the entry as suppressed;
// the count rides along on the next send so nothing disappears silently.
func (e *escalator) note(source string, cfg *escalateCfg, en entry, post notifyFn) {
	e.mu.Lock()
	if time.Since(e.last[source]) < e.window {
		e.suppressed[source]++
		e.mu.Unlock()
		return
	}
	n := e.suppressed[source]
	e.suppressed[source] = 0
	e.last[source] = time.Now()
	e.sent[source]++
	e.mu.Unlock()

	text := "🪵 " + source + " " + levelName(en.level) + ": " + truncate(en.msg, 300)
	if n > 0 {
		text += fmt.Sprintf(" (+%d suppressed)", n)
	}
	go post(cfg, text)
}

func (e *escalator) sentCounts() map[string]int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[string]int64, len(e.sent))
	for k, v := range e.sent {
		out[k] = v
	}
	return out
}

// postNotify delivers one message to notify-relay. No retries here: the relay
// has its own retry loop toward Signal, and a lost escalation is recoverable —
// the log row itself is already stored.
func (s *server) postNotify(cfg *escalateCfg, text string) {
	token := cfg.Token
	if token == "" {
		token = s.notifyToken
	}
	if token == "" || cfg.NotifySource == "" {
		return
	}
	body, _ := json.Marshal(map[string]string{"message": text})
	req, err := http.NewRequest("POST", s.notifyURL+"/hook/"+cfg.NotifySource, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("escalate %s: %v", cfg.NotifySource, err)
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		log.Printf("escalate %s: status %s", cfg.NotifySource, resp.Status)
	}
}
