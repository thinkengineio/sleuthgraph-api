# Plugin Catalog

Sleuthgraph ships with 11 plugins: 8 free-tier and 3 BYOK (bring your own API key).

Each plugin accepts one or more entity types (`entity_types_accepted`) and
produces zero or more new entities, typed relationships, and an evidence row
capturing the raw upstream response.

## Free plugins (no API key required)

| Plugin | Description | Accepts | Produces | Upstream |
|--------|-------------|---------|----------|----------|
| `crtsh` | Certificate Transparency subdomain discovery | DOMAIN | DOMAIN | <https://crt.sh> |
| `dns_whois` | DNS lookup + RDAP/WHOIS registration data | DOMAIN | DOMAIN, IP_ADDRESS | DNS + <https://rdap.org> |
| `wayback_cdx` | Wayback Machine archived URL enumeration | DOMAIN, URL | URL | <http://web.archive.org/cdx/search/cdx> |
| `opencorporates` | Company registry search across 140+ jurisdictions | PERSON, ORGANIZATION | ORGANIZATION | <https://api.opencorporates.com/v0.4/companies/search> |
| `github_public` | GitHub public profile lookup | PERSON, EMAIL | PERSON | <https://api.github.com> |
| `opensanctions` | Sanctions and PEP screening | PERSON, ORGANIZATION | (evidence only) | <https://api.opensanctions.org/search/default> |
| `aleph_occrp` | OCCRP Aleph document and entity search | PERSON, ORGANIZATION | (evidence only) | <https://aleph.occrp.org/api/2/entities> |
| `urlhaus` | Malware URL/domain reputation database | URL, DOMAIN | (evidence only) | <https://urlhaus-api.abuse.ch/v1/> |

## BYOK plugins (bring your own API key)

These plugins require a personal API key registered with the upstream service.
Keys are stored encrypted in the credential vault and never logged.

| Plugin | Description | Accepts | Produces | Key required | Where to get a key |
|--------|-------------|---------|----------|-------------|-------------------|
| `virustotal` | File, URL, and domain multi-engine analysis | DOMAIN, IP_ADDRESS, URL | DOMAIN, IP_ADDRESS, URL | Yes | <https://www.virustotal.com/gui/my-apikey> |
| `shodan` | Internet-wide scan data: ports, services, vulns | IP_ADDRESS | DOMAIN | Yes | <https://account.shodan.io/> |
| `hibp` | Have I Been Pwned breach database search | EMAIL | (evidence only) | Yes | <https://haveibeenpwned.com/API/Key> |

## Plugin guarantees (all plugins)

- Response body capped at 10 MiB. Anything larger aborts with `upstream_network_error`.
- Per-plugin hard cap on entity proposals (see the `MAX_*` constants in each module).
- `tenacity` retry with exponential back-off on transient HTTP failures (3 attempts).
- Evidence `reproducibility_spec` always includes `url`, `method`, `queried_at`,
  and relevant count/truncation metadata.
- 404 responses from upstream APIs that mean "not found" (e.g. HIBP no breaches,
  crt.sh empty) return an empty `QueryResult`, not an error.

## Dispatch modes

- **sync** — Plugin executes in the HTTP request context and returns 201 with the
  full result payload. Typical for sources with latency under 5 s.
- **async** — Plugin creates a `PluginRun` with `status=queued`, enqueues a job on
  the `arq` Redis queue, and returns 202 immediately. The client polls
  `GET /cases/{case_id}/plugins/runs/{run_id}` until the status moves
  `queued → running → succeeded | failed`. Currently only `wayback_cdx` uses
  async dispatch.

### Running the async worker

```sh
arq sleuthgraph.queue.arq_settings.WorkerSettings
```

The worker reuses the main app's Redis (`REDIS_URL`) unless `ARQ_REDIS_URL`
overrides it. See `deploy/docker-compose.yml` for the containerised service
definition.

## Adding a new plugin

1. Subclass `OSINTPlugin` (or `BYOKPlugin` for key-gated plugins) under
   `src/sleuthgraph/plugins/builtin/<name>.py`.
2. Register the instance in `src/sleuthgraph/plugins/__init__.py::PLUGINS`.
3. Write unit tests at `tests/test_plugin_<name>.py`. Use `httpx.MockTransport`
   to stub upstream HTTP.
4. Follow the existing shape: 10 MiB cap, proposal cap constants,
   tenacity-retried `_fetch`, input validation before URL construction
   (CWE-74), and `reproducibility_spec` with `url`, `method`, `queried_at`,
   and any counts/flags the UI might surface.
5. For BYOK plugins: extend `BYOKPlugin`, set `credential_name` and
   `credential_url`, and read `credentials["api_key"]` in `query()`.
   Never embed the key in a URL path or query string visible in evidence.
