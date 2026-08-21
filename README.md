# logbook — one log sink for every app

Centralized logging at `https://logs.gawaak.ovh`. One Go binary, one SQLite
file (WAL, single writer). Apps write with a per-source bearer token; agents
read everything back with one global read token — grep-friendly text by
default, raw SQL when the filters run out.

## Write (fire-and-forget)

```sh
# plain text → level info
curl -s -H "Authorization: Bearer $TOK" --data-binary "nightly update ok" \
     https://logs.gawaak.ovh/log/cron

# JSON: level, msg, meta, optional client ts (ms)
curl -s -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' -d \
  '{"level":"error","msg":"vtt-failed vid=abc","meta":{"version":"1.0.24"}}' \
  https://logs.gawaak.ovh/log/youtube-app
```

A JSON **array** of such objects is one batched request. Clients must swallow
errors and never retry on user paths — an unreachable logger must not break an
app. The server is symmetrically forgiving: unknown levels become `info`,
oversize input is truncated (64 KB body / 4 KB msg / 8 KB meta), never
rejected. Rate limit 60/min sustained, burst 300, per source; excess gets 429
and a drop counter. Success is `204`.

Shell helper worth pasting into any cron script:

```sh
logto() { curl -sm 5 -H "Authorization: Bearer $LOGBOOK_TOKEN" \
  --data-binary "$*" https://logs.gawaak.ovh/log/cron >/dev/null 2>&1 || true; }
```

## Read (agents)

```sh
TOK=$(cat ~/.logbook-read-token)

# filters: source, level (min), since (30m/2h/3d | RFC3339 | unix), q
# (substring), meta.<key>=<value>, before, limit (default 100, max 1000)
curl -s -H "Authorization: Bearer $TOK" \
  'https://logs.gawaak.ovh/api/logs?source=youtube-app&since=1h&level=warn'

# raw SELECT over the logs table (query_only, 2s timeout, 1000-row cap);
# TSV by default, JSON with Accept: application/json
curl -s -H "Authorization: Bearer $TOK" -d \
  "SELECT msg, count(*) FROM logs WHERE level=3 GROUP BY msg ORDER BY 2 DESC LIMIT 10" \
  https://logs.gawaak.ovh/api/query

# live tail (SSE)
curl -sN -H "Authorization: Bearer $TOK" 'https://logs.gawaak.ovh/api/tail?level=error'
```

`GET /api/logs` returns text lines `<iso-ms> <level> <source> <msg> <meta>`;
`Accept: application/json` gets structured rows. Schema for /api/query:
`logs(id, ts, client_ts, source, level, msg, meta)` — ts in ms, level 0
debug · 1 info · 2 warn · 3 error, meta JSON (use `json_extract(meta,'$.k')`).

## Web UI

`GET /` is a slim viewer (filters + SSE tail) that signs in through
auth.gawaak.ovh and calls the same read API with the broker id_token.
`ALLOWED_EMAILS` (csv) restricts who counts; empty means any verified broker
account.

## Config — `/data/sources.json` (hot-reloaded)

```json
{
  "youtube-app": { "token": "…", "retentionDays": 14,
                   "escalate": { "minLevel": "error", "notifySource": "adhoc" } },
  "cron":        { "token": "…", "retentionDays": 30 }
}
```

Escalation forwards matching entries to `notify.gawaak.ovh/hook/<notifySource>`
(Signal), throttled to one per source per 5 minutes with a suppressed count on
the next send; logbook never talks to Signal directly. The escalate token
defaults to `NOTIFY_TOKEN`.

## Retention & safety

Hourly sweeper deletes rows older than each source's `retentionDays`
(default 14). Global cap `DB_MAX_MB` (default 512): oldest rows are trimmed
regardless of source, then pages are returned via `incremental_vacuum`. A
leaked write token can produce noise only — bounded by the rate limit, size
caps and the cap on the file itself.

## Env

| var | default | |
|---|---|---|
| `LISTEN` | `:8080` | |
| `DB_PATH` | `/data/logbook.db` | |
| `CONFIG` | `/data/sources.json` | `SOURCES_JSON` env as fallback |
| `READ_TOKEN` | — | the one global read credential |
| `ADMIN_PATH` | — | stats at `/admin/<ADMIN_PATH>` |
| `DB_MAX_MB` | `512` | |
| `NOTIFY_URL` | `https://notify.gawaak.ovh` | |
| `NOTIFY_TOKEN` | — | default escalation token |
| `AUTH_ISSUER` | `https://auth.gawaak.ovh` | |
| `BASE_URL` | `https://logs.gawaak.ovh` | audience for broker tokens |
| `ALLOWED_EMAILS` | — | csv; empty = any verified broker account |

Deployed via Coolify (dockerfile pack): volume at `/data`, `sources.json` as a
file mount, 128 MB memory limit.
