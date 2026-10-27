# RBAC Auth API

A runnable Spring Boot backend for the security experiment: JWT access-token authentication, role-protected endpoints, rotating refresh tokens, and encrypted storage for third-party OAuth credentials.

## Requirements

- Java 21 or later
- Maven 3.9+ (or the included Maven Wrapper)

## Run on Windows

```powershell
.\run.ps1
```

The first run creates `.env.local` with persistent random signing/encryption keys and a random local administrator password, then starts the API on `http://localhost:8080`. `.env.local` is ignored by Git. Keep it private and back it up: changing or losing `CREDENTIAL_ENCRYPTION_KEY` makes previously stored credentials unreadable.

The local administrator username is `admin`; its generated password is in `.env.local`. Do not use the local HTTP cookie setting or local credentials in production. For a production deployment, supply strong secrets through a secret manager, set `COOKIE_SECURE=true`, and serve the API over HTTPS.

To run tests:

```powershell
.\mvnw.cmd test
```

If you do not have the wrapper yet, use `mvn test` with Maven 3.9+.

## API

| Method | Path | Access | Purpose |
|---|---|---|---|
| `GET` | `/api/health` | Public | Health check |
| `POST` | `/api/auth/register` | Public | Register a `USER` and issue tokens |
| `POST` | `/api/auth/login` | Public | Authenticate and issue tokens |
| `POST` | `/api/auth/refresh` | Refresh cookie | Rotate refresh token and issue a new access token |
| `POST` | `/api/auth/logout` | Refresh cookie | Revoke refresh token and clear its cookie |
| `GET` | `/api/users/me` | Authenticated | Return the current user and roles |
| `GET` | `/api/admin` | `ADMIN` role | Demonstrate role-based authorization |
| `POST` | `/api/credentials` | Authenticated | Store an encrypted OAuth token |
| `GET` | `/api/credentials` | Authenticated | List the current user's credential metadata |
| `GET` | `/api/credentials/{id}/secret` | Credential owner | Decrypt and return the selected token |
| `DELETE` | `/api/credentials/{id}` | Credential owner | Delete the selected credential |

New registrations receive only the `USER` role. The configured bootstrap administrator is created on first startup only when its username does not already exist. Refresh tokens are opaque, stored only as SHA-256 hashes, and rotated on use; replaying a revoked token revokes its active token family. Access JWTs expire after 15 minutes by default.

Refresh tokens are sent only in an `HttpOnly`, `SameSite=Strict` cookie scoped to `/api/auth`; access tokens are returned in the response body and should be sent as `Authorization: Bearer <accessToken>`. Secret-reveal responses are marked `Cache-Control: no-store`. The API does not log credential values.

### Example requests (PowerShell)

Register a user (the refresh token is returned as an HttpOnly cookie):

```powershell
$body = @{ username = "alice"; password = "a-long-unique-password" } | ConvertTo-Json
$session = Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/auth/register `
  -ContentType "application/json" -Body $body -SessionVariable apiSession
$headers = @{ Authorization = "Bearer $($session.accessToken)" }
```

Inspect the current user, then store a third-party token without returning it in the create response:

```powershell
Invoke-RestMethod -Uri http://localhost:8080/api/users/me -Headers $headers
$credential = @{ provider = "github"; token = "replace-with-a-provider-token" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/credentials `
  -Headers $headers -ContentType "application/json" -Body $credential
```

Refresh with the same web session so the browser/client sends the cookie:

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/auth/refresh `
  -WebSession $apiSession
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `JWT_SECRET` | Required | Base64-encoded HMAC key; at least 32 decoded bytes |
| `CREDENTIAL_ENCRYPTION_KEY` | Required | Base64-encoded AES key; exactly 32 decoded bytes |
| `ACCESS_TOKEN_TTL` | `PT15M` | Access-token lifetime as an ISO-8601 duration |
| `REFRESH_TOKEN_TTL` | `PT168H` | Refresh-token lifetime as an ISO-8601 duration |
| `COOKIE_SECURE` | `false` | Set `true` when serving over HTTPS |
| `ADMIN_USERNAME` | Empty | Optional first-start administrator username |
| `ADMIN_PASSWORD` | Empty | Optional first-start administrator password (at least 12 characters) |
| `DATABASE_URL` | H2 file database | JDBC URL for the included H2 database |

The development runner persists random keys in `.env.local` so database credentials remain decryptable across restarts. Production deployments should inject secrets from a secret manager. Changing the credential encryption key requires re-encrypting stored credentials before the old key is retired.

The included H2 database and Hibernate `ddl-auto: update` setting are for this runnable demonstration. A production database requires its JDBC driver and migration-managed schema.
