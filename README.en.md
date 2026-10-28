[🇩🇪 Deutsch](README.md) · 🇬🇧 English

# UniFi API Guard

A small permissions proxy for the **UniFi Network Integration API** (UniFi Network 9.4+).

UniFi API keys have no permission levels: whoever holds the key can change the whole network through the API –
firewall, VLANs, WLANs. UniFi API Guard sits between your applications and the gateway. It holds the real UniFi key,
and each application gets its **own key with exactly the permissions it needs**.

**Guide:** [docs/anleitung.md](docs/anleitung.md) (German) · **Changes:** [CHANGELOG.md](CHANGELOG.md) (German)

```
NPMplus ──(Guard key: only DNS records *.example.com)──┐
Home Assistant ──(Guard key: read devices/clients)─────┼──► UniFi API Guard ──(UniFi key)──► UniFi gateway
Script ──(Guard key: read-only)────────────────────────┘
```

> The admin UI is currently in German. UI labels are quoted in German below, with an English gloss on first mention.

## Features

- **Same API as the gateway:** paths under `/proxy/network/integration/v1/` and the `X-API-KEY` header stay the same.
  Applications only need a different URL and a different key.
- **Rules per key, everything else is denied:** HTTP methods × endpoint, optionally with an **object filter**
  (e.g. only DNS records whose `domain` matches `*.example.com`). Rules are built in a form:
  pick an endpoint from a list of the UniFi Network API or enter a custom path, tick the methods. JSON remains
  available as an expert mode.
  - Lists are filtered (foreign entries are invisible, paging stays correct).
  - Foreign single objects return `404`.
  - On create/update the body is checked, and on update/delete the existing object is checked as well –
    a foreign entry can be neither modified, deleted nor "taken over".
- **IP allowlist per key** (mandatory; empty = blocked).
- **Templates:** local DNS records (e.g. for NPMplus), read-only, read devices and clients (e.g. Home Assistant),
  custom rules.
- **Rate limit per key**, size and time limits for requests.
- **Log** of the most recent requests in the UI (key name, IP, method, path, allowed/denied).
  Keys and request bodies are never logged.
- **Stored securely:** Guard keys only as SHA-256 hashes (shown once), UniFi key AES-GCM encrypted,
  admin password PBKDF2-SHA256, configuration file with mode `0600`.
- **Gateway certificate:** fingerprint pinning (recommended for self-signed certificates), CA validation, or off.
- **Small:** a single static Go binary without external dependencies, distroless image without a shell, runs as a
  non-root user.

## Getting started

```yaml
# compose.yaml
services:
  unifi-api-guard:
    image: ghcr.io/hotte512/unifi-api-guard:latest
    container_name: unifi-api-guard
    restart: unless-stopped
    ports:
      - "8080:8080"            # proxy for applications
      - "127.0.0.1:8081:8081"  # admin UI
    volumes:
      - ./data:/data
```

```bash
docker compose up -d
```

```bash
docker logs unifi-api-guard
```

On first start the Guard creates a **setup token**: in the file `setup-token` in the data directory
(`cat data/setup-token`) and in the log. Open the admin UI (`http://127.0.0.1:8081`), enter the token
and set an admin password. The token is worthless afterwards.

The data directory must be writable for the container user (UID 65532):

```bash
mkdir -p data && sudo chown 65532:65532 data
```

## Together with NPMplus on one host

If the Guard runs on the same host (or LXC) as NPMplus, host mode is the simplest: the proxy listens only on
`127.0.0.1`, NPMplus uses `http://127.0.0.1:8090` and the allowed IP `127.0.0.1`.

```yaml
services:
  unifi-api-guard:
    image: ghcr.io/hotte512/unifi-api-guard:latest
    container_name: unifi-api-guard
    restart: unless-stopped
    network_mode: host
    environment:
      GUARD_PROXY_ADDR: 127.0.0.1:8090
      GUARD_ADMIN_ADDR: :8091
    volumes:
      - /opt/unifi-api-guard:/data
```

```bash
sudo mkdir -p /opt/unifi-api-guard && sudo chown 65532:65532 /opt/unifi-api-guard
```

The [NPMplus Hotte installer](https://github.com/Hotte512/NPMplus) (branch `claude/hotte-ci`, `install/install.sh`
or `install/proxmox.sh`) sets this up automatically. More in the [guide](docs/anleitung.md) (German).

## Setup

1. **Create a UniFi key:** *UniFi Network › Settings › Integrations*. Ideally with a dedicated local admin.
2. **Enter the gateway:** URL (e.g. `https://192.168.1.1`) and key. Click "Fingerprint abrufen" (fetch fingerprint),
   compare it with the gateway's certificate, save. Then "Verbindung testen" (test connection).
3. **Create a key for an application:** name, template, domains if needed, allowed IPs. The key is shown only once.
   The template "Eigene Regeln" (custom rules) creates a key without rules; add them afterwards in the form.

### NPMplus

Template **"Lokale DNS-Einträge"** (local DNS records), domains e.g. `*.example.com`, allowed IP = IP of the NPMplus
host (e.g. `192.168.1.10`). In NPMplus under *Einstellungen › UniFi Local DNS* (Settings › UniFi Local DNS):

| Field | Value |
| --- | --- |
| Gateway-URL (gateway URL) | `http://192.168.1.x:8080` (address of the Guard) |
| API-Key | the Guard key (`uag_…`) |
| TLS prüfen (verify TLS) | according to the Guard configuration (irrelevant for HTTP) |

### Home Assistant

Template **"Geräte und Clients lesen"** (read devices and clients) or **"Nur lesen"** (read-only), allowed IP = Home
Assistant. In the integration or REST sensor, use the Guard URL and the Guard key.

## Rules

Each key has a list of rules (JSON, editable in the UI). Paths are relative to
`/proxy/network/integration/v1/`; `*` stands for exactly one segment, `**` at the end for any number of segments.

```json
[
  { "methods": ["GET"], "path": "sites" },
  { "methods": ["GET", "POST"], "path": "sites/*/dns/policies",
    "filter": { "field": "domain", "patterns": ["*.example.com"] } },
  { "methods": ["GET", "PUT", "DELETE"], "path": "sites/*/dns/policies/*",
    "filter": { "field": "domain", "patterns": ["*.example.com"] } }
]
```

Filter patterns: `example.com` = exactly this domain, `*.example.com` = all subdomains (not `example.com` itself),
`*` = everything.

## Configuration (environment variables)

| Variable | Default | Meaning |
| --- | --- | --- |
| `GUARD_DATA_DIR` | `/data` | Configuration (`config.json`) and, if applicable, `secret.key` |
| `GUARD_PROXY_ADDR` | `:8080` | Proxy port for applications |
| `GUARD_ADMIN_ADDR` | `:8081` | Admin UI |
| `GUARD_ADMIN_ALLOW` | private networks | IPs/networks allowed to open the admin UI (comma-separated) |
| `GUARD_TRUSTED_PROXIES` | empty | Reverse proxies whose `X-Forwarded-For` is trusted |
| `GUARD_SECRET_FILE` | `$GUARD_DATA_DIR/secret.key` | Key used to encrypt the UniFi key (64 hex characters, generated otherwise) |
| `GUARD_TLS_CERT`, `GUARD_TLS_KEY` | empty | HTTPS for both ports |
| `GUARD_COOKIE_SECURE` | `false` | `true` if the admin UI runs behind an HTTPS reverse proxy |

## Security notes

- Do **not expose the admin port to the internet**, and ideally make it reachable only from the admin network.
- The proxy port speaks HTTP by default. That is usually sufficient on a LAN; otherwise set
  `GUARD_TLS_CERT`/`GUARD_TLS_KEY` or put a reverse proxy in front.
- If `secret.key` lives in the same volume as `config.json`, the encryption only protects against reading the
  configuration file alone (e.g. from backups). Better: point `GUARD_SECRET_FILE` at a Docker secret.
- If the Guard is compromised, the UniFi key is affected too. The Guard reduces the risk to this one very small
  service – instead of every application that uses the API.

## Development

```bash
go test -race ./...
```

```bash
go run ./cmd/unifi-api-guard
```

(with `GUARD_DATA_DIR=./data`). Examples in docs and tests only with `example.com` and `192.168.1.x`.

## Disclaimer and notes

- **No warranty, no liability.** Private hobby project, use at your own risk. The Guard reduces the risk of a UniFi
  API key but does not replace your own review of the rules or a backup of the gateway configuration.
- **Developed with AI assistance.** Code and docs are produced with the help of AI (Claude), reviewed and
  tested (unit and end-to-end tests, `govulncheck`), but may still contain mistakes.
- Not affiliated with Ubiquiti. "UniFi" is a trademark of Ubiquiti Inc.

## License

MIT, see [LICENSE](LICENSE).
