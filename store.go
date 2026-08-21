// The storage layer: one SQLite file in WAL mode, one writer connection, a
// small pool of query_only readers. modernc.org/sqlite keeps it pure Go, so
// the binary is CGO-free and the Docker image trivial.
package main

import (
	"context"
	"database/sql"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// levels: 0 debug · 1 info · 2 warn · 3 error. Stored as integers so
// level>=? is an index-friendly comparison.
var levelNames = [...]string{"debug", "info", "warn", "error"}

func levelName(n int) string {
	if n < 0 || n >= len(levelNames) {
		return "info"
	}
	return levelNames[n]
}

// parseLevel is permissive on purpose: unknown levels become info rather than
// rejecting the write — an unloggable log line defeats the whole service.
func parseLevel(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug", "trace":
		return 0
	case "warn", "warning":
		return 2
	case "error", "err", "fatal", "panic":
		return 3
	default:
		return 1
	}
}

type entry struct {
	id       int64
	ts       int64 // server receive, ms — the ordering truth
	clientTS *int64
	source   string
	level    int
	msg      string
	meta     string // compact JSON or ""
}

// textLine renders the grep-friendly wire format:
//
//	2026-08-21T10:58:11.204Z error youtube-app vtt-failed vid=… {"status":403}
//
// Newlines inside msg are escaped so one entry is always one line — both grep
// and the SSE framing depend on that.
func textLine(e entry) string {
	t := time.UnixMilli(e.ts).UTC().Format("2006-01-02T15:04:05.000Z")
	line := t + " " + levelName(e.level) + " " + e.source + " " + strings.ReplaceAll(e.msg, "\n", "\\n")
	if e.meta != "" {
		line += " " + e.meta
	}
	return line
}

type store struct {
	db       *sql.DB // single-writer: MaxOpenConns(1)
	rdb      *sql.DB // query_only readers
	maxBytes int64
}

func openStore(path string, maxBytes int64) (*store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)

	// auto_vacuum must be decided before the first table exists; for a DB that
	// predates the setting, one VACUUM rebuilds it. Needed so the sweeper's
	// incremental_vacuum actually returns pages to the OS after cap trims.
	var av int
	if err := db.QueryRow(`PRAGMA auto_vacuum`).Scan(&av); err != nil {
		return nil, err
	}
	if av != 2 {
		if _, err := db.Exec(`PRAGMA auto_vacuum=incremental`); err != nil {
			return nil, err
		}
		if _, err := db.Exec(`VACUUM`); err != nil {
			return nil, err
		}
	}
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS logs (
  id        INTEGER PRIMARY KEY,
  ts        INTEGER NOT NULL,   -- server receive, ms
  client_ts INTEGER,
  source    TEXT NOT NULL,
  level     INTEGER NOT NULL,   -- 0 debug · 1 info · 2 warn · 3 error
  msg       TEXT NOT NULL,
  meta      TEXT                -- JSON or NULL
);
CREATE INDEX IF NOT EXISTS idx_logs_source_ts ON logs(source, ts);
CREATE INDEX IF NOT EXISTS idx_logs_ts        ON logs(ts);`); err != nil {
		return nil, err
	}

	// The read pool carries query_only both as our own /api/query guardrail
	// and as insurance that no read path can ever write.
	rdb, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(2000)&_pragma=query_only(1)")
	if err != nil {
		return nil, err
	}
	rdb.SetMaxOpenConns(4)
	return &store{db: db, rdb: rdb, maxBytes: maxBytes}, nil
}

// insert writes a batch in one transaction and stamps the generated ids/ts
// back onto the entries so callers can publish them to the tail hub.
func (st *store) insert(entries []entry) error {
	if len(entries) == 0 {
		return nil
	}
	tx, err := st.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO logs (ts, client_ts, source, level, msg, meta) VALUES (?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for i := range entries {
		e := &entries[i]
		var meta any
		if e.meta != "" {
			meta = e.meta
		}
		var cts any
		if e.clientTS != nil {
			cts = *e.clientTS
		}
		res, err := stmt.Exec(e.ts, cts, e.source, e.level, e.msg, meta)
		if err != nil {
			return err
		}
		e.id, _ = res.LastInsertId()
	}
	return tx.Commit()
}

// logsQuery is the /api/logs filter set, all executed in SQLite.
type logsQuery struct {
	source   string
	minLevel int
	since    int64 // ms, 0 = unbounded
	before   int64 // ms, 0 = unbounded
	q        string
	meta     map[string]string // key (json path tail) → value, compared as text
	limit    int
}

// query returns the newest matching rows in chronological order — "the last N
// logs", which is what every debugging session actually wants.
func (st *store) query(ctx context.Context, lq logsQuery) ([]entry, error) {
	where, args := []string{"1=1"}, []any{}
	if lq.source != "" {
		where, args = append(where, "source = ?"), append(args, lq.source)
	}
	if lq.minLevel > 0 {
		where, args = append(where, "level >= ?"), append(args, lq.minLevel)
	}
	if lq.since > 0 {
		where, args = append(where, "ts >= ?"), append(args, lq.since)
	}
	if lq.before > 0 {
		where, args = append(where, "ts < ?"), append(args, lq.before)
	}
	if lq.q != "" {
		esc := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(lq.q)
		where, args = append(where, `msg LIKE ? ESCAPE '\'`), append(args, "%"+esc+"%")
	}
	for k, v := range lq.meta {
		where, args = append(where, "CAST(json_extract(meta, ?) AS TEXT) = ?"), append(args, "$."+k, v)
	}
	limit := lq.limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	rows, err := st.rdb.QueryContext(ctx,
		`SELECT id, ts, client_ts, source, level, msg, COALESCE(meta,'') FROM logs WHERE `+
			strings.Join(where, " AND ")+` ORDER BY id DESC LIMIT ?`, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []entry
	for rows.Next() {
		var e entry
		var cts sql.NullInt64
		if err := rows.Scan(&e.id, &e.ts, &cts, &e.source, &e.level, &e.msg, &e.meta); err != nil {
			return nil, err
		}
		if cts.Valid {
			e.clientTS = &cts.Int64
		}
		out = append(out, e)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, rows.Err()
}

// sweep enforces retention and the global size cap. Retention is per source
// (default 14 days); the cap trims oldest rows regardless of source, then
// hands pages back via incremental_vacuum. Runs hourly and at startup.
func (st *store) sweep(cfg config) error {
	now := time.Now().UnixMilli()
	day := int64(24 * time.Hour / time.Millisecond)

	names := make([]any, 0, len(cfg))
	for name, sc := range cfg {
		days := sc.RetentionDays
		if days <= 0 {
			days = defaultRetentionDays
		}
		if _, err := st.db.Exec(`DELETE FROM logs WHERE source = ? AND ts < ?`, name, now-int64(days)*day); err != nil {
			return err
		}
		names = append(names, name)
	}
	// Sources that have since left the config still decay at the default rate.
	q := `DELETE FROM logs WHERE ts < ?`
	args := []any{now - defaultRetentionDays*day}
	if len(names) > 0 {
		q += ` AND source NOT IN (?` + strings.Repeat(",?", len(names)-1) + `)`
		args = append(args, names...)
	}
	if _, err := st.db.Exec(q, args...); err != nil {
		return err
	}

	for range 50 { // bounded: each pass frees 5000 rows or bails
		size, err := st.sizeBytes()
		if err != nil || size <= st.maxBytes {
			return err
		}
		res, err := st.db.Exec(`DELETE FROM logs WHERE id IN (SELECT id FROM logs ORDER BY ts LIMIT 5000)`)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			break
		}
		// incremental_vacuum frees one page per step, so it must be drained
		// as a query — a bare Exec steps once and frees a single page.
		vr, err := st.db.Query(`PRAGMA incremental_vacuum`)
		if err != nil {
			return err
		}
		for vr.Next() {
		}
		if err := vr.Close(); err != nil {
			return err
		}
	}
	_, err := st.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	return err
}

func (st *store) sizeBytes() (int64, error) {
	var pages, pageSize int64
	if err := st.db.QueryRow(`PRAGMA page_count`).Scan(&pages); err != nil {
		return 0, err
	}
	if err := st.db.QueryRow(`PRAGMA page_size`).Scan(&pageSize); err != nil {
		return 0, err
	}
	return pages * pageSize, nil
}

// sourceStat feeds the admin endpoint.
type sourceStat struct {
	Rows   int64 `json:"rows"`
	Oldest int64 `json:"oldestTs,omitempty"`
	Newest int64 `json:"newestTs,omitempty"`
}

func (st *store) stats() (map[string]*sourceStat, error) {
	rows, err := st.rdb.Query(`SELECT source, count(*), min(ts), max(ts) FROM logs GROUP BY source`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*sourceStat{}
	for rows.Next() {
		var name string
		s := &sourceStat{}
		if err := rows.Scan(&name, &s.Rows, &s.Oldest, &s.Newest); err != nil {
			return nil, err
		}
		out[name] = s
	}
	return out, rows.Err()
}
