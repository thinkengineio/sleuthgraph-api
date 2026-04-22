# Built-in OSINT Plugins (Phase 6)

Sleuthgraph ships with 8 free-tier OSINT plugins. None require paid credentials.

Each plugin accepts one or more entity types (its `entity_types_accepted`) and
produces zero or more new entities, typed relationships, and an evidence row
capturing the raw upstream response.

| Plugin | Accepts | Produces | Upstream | Dispatch | Rate limit |
|--------|---------|----------|----------|----------|------------|
| `crtsh` | DOMAIN | DOMAIN (subdomain) | <https://crt.sh> | sync | Courtesy |
| `dns_whois` | DOMAIN | IP_ADDRESS, DOMAIN (ns/mx) | DNS + <https://rdap.org> | sync | DNS-level |
| `wayback_cdx` | DOMAIN, URL | URL | <http://web.archive.org/cdx/search/cdx> | **async** | Courtesy |
| `opencorporates` | PERSON, ORGANIZATION | ORGANIZATION | <https://api.opencorporates.com/v0.4/companies/search> | sync | Free tier |
| `github_public` | PERSON, EMAIL | PERSON | <https://api.github.com> | sync | 60 req/hr anon |
| `opensanctions` | PERSON, ORGANIZATION | (evidence only) | <https://api.opensanctions.org/search/default> | sync | Public |
| `aleph_occrp` | PERSON, ORGANIZATION | (evidence only) | <https://aleph.occrp.org/api/2/entities> | sync | Public |
| `urlhaus` | URL, DOMAIN | (evidence only) | <https://urlhaus-api.abuse.ch/v1/> | sync | Public |

All plugins share these guarantees:

- Response body capped at 10 MiB (anything larger aborts with `upstream_network_error`).
- Per-plugin hard cap on proposals (see the `MAX_*` constants in each module).
- `tenacity` retry with exponential back-off on transient HTTP failures.
- Evidence `reproducibility_spec` always includes `url`, `method`, `queried_at`,
  and relevant count/truncation metadata.
- No API key is required; BYOK variants (HIBP, VirusTotal, etc.) are deferred
  to Phase 7.

## Dispatch modes

- **sync** plugins execute in the HTTP request context and return 201 with the
  full result payload. Fast sources (typical latency < 5 s).
- **async** plugins create a `PluginRun` with `status=queued`, enqueue a job on
  the `arq` Redis queue, and return 202 immediately. The client polls
  `GET /cases/{case_id}/plugins/runs/{run_id}` to observe the status move
  `queued → running → succeeded | failed`. Currently only `wayback_cdx` opts in.

## Running the async worker

```sh
arq sleuthgraph.queue.arq_settings.WorkerSettings
```

The worker reuses the main app's Redis (`REDIS_URL`) unless `ARQ_REDIS_URL`
overrides it. See `deploy/docker-compose.yml` for the containerized service
definition.

## Adding a new plugin

1. Subclass `OSINTPlugin` under `src/sleuthgraph/plugins/builtin/<name>.py`.
2. Register the instance in `src/sleuthgraph/plugins/__init__.py::PLUGINS`.
3. Write unit tests at `tests/test_plugin_<name>.py`. Use `httpx.MockTransport`
   to stub upstream HTTP.
4. Follow the existing shape: 10 MiB cap, proposal cap constants,
   tenacity-retried `_fetch`, and `reproducibility_spec` with `url`, `method`,
   `queried_at`, and any counts/flags the UI might surface.
