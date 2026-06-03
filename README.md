# OAuth 2.0 Dummy Endpoint

A minimal, OAuth 2.0–compliant authorization server for demos and integration testing. Implements the **Client Credentials** grant (RFC 6749 §4.4) and issues signed **JWT** access tokens (RFC 9068). Designed to run on [render.com](https://render.com) with zero config.

## Endpoints

| Method | Path                                              | Purpose                              |
| ------ | ------------------------------------------------- | ------------------------------------ |
| POST   | `/oauth/token`                                    | Issue an access token                |
| POST   | `/oauth/introspect`                               | Validate / introspect a token (RFC 7662) |
| GET    | `/oauth/userinfo`                                 | Return claims for the bearer token   |
| GET    | `/.well-known/oauth-authorization-server`         | RFC 8414 metadata document           |
| GET    | `/healthz`                                        | Liveness probe                       |
| GET    | `/docs`                                           | Swagger UI for the OpenAPI spec      |
| GET    | `/openapi.yaml`                                   | Raw OpenAPI 3.1 spec                 |

## Quick start

```bash
npm install
cp .env.example .env
npm start
```

Get a token:

```bash
curl -X POST http://localhost:3000/oauth/token \
  -u demo-client:demo-secret \
  -d "grant_type=client_credentials&scope=read write"
```

Introspect a token:

```bash
curl -X POST http://localhost:3000/oauth/introspect \
  -u demo-client:demo-secret \
  -d "token=<access_token>"
```

## Deploy to render.com

1. Push this repo to GitHub.
2. In render.com, **New → Blueprint**, point at the repo. `render.yaml` is auto-detected.
3. After deploy, set `JWT_ISSUER` to the public URL (e.g. `https://oauth2-dummy.onrender.com`).
4. Test: `curl -X POST https://<your-service>.onrender.com/oauth/token -u demo-client:demo-secret -d grant_type=client_credentials`

## Configuration

Environment variables (see `.env.example`):

- `OAUTH_CLIENTS` — comma-separated `id:secret:scope1 scope2` entries
- `JWT_SECRET` — HS256 signing secret
- `JWT_ISSUER` — value used as the `iss` claim
- `TOKEN_TTL` — access-token lifetime in seconds (default 3600)
- `PORT` — defaults to 3000

## Notes

This is a **dummy** server for testing. Tokens are signed with a shared HS256 secret so the consuming app needs the same secret to verify offline, or it can call `/oauth/introspect`. Do not use as-is in production.
