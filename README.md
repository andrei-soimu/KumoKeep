# KumoKeep
A small cloud for the things you keep.

Self-hosted, multi-user files, notes, photos and a password vault (compatible with
Bitwarden clients), in one lightweight Go binary. Design and decisions:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Layout

| Path | What |
|---|---|
| `server/` | Go backend (`kumokeep` binary) |
| `web/` | SvelteKit web app, embedded into the binary |
| `mobile/` | Flutter app (planned) |
| `api/openapi.yaml` | API contract |
| `deploy/` | Dockerfile, Caddyfile |

## Development

Requires Go 1.26+ and Node 22+.

```bash
make generate                # sqlc code from SQL (after changing migrations/queries)
make dev-server              # API on 127.0.0.1:8080, data in ./data
make dev-web                 # web app with hot reload, proxies /api
```

Create the first admin (prompts for a password):

```bash
cd server && KUMOKEEP_DATA_DIR=../data go run ./cmd/kumokeep admin create --username admin --email you@example.com
```

Build a single binary with the web app embedded:

```bash
make web server              # → server/bin/kumokeep
make test
```

## License

AGPL-3.0. See [LICENSE](LICENSE).
