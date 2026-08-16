# SecureGate Auth Architecture & Security Model

## 1. Overview

SecureGate is an OAuth2/JWT gateway that authenticates and authorizes requests to platform microservices (metrics-ingest, pulsealert, statushub, etc.). It issues JWTs, enforces RBAC, manages API keys, and applies rate limits.

---

## 2. JWT Authentication Flow

### 2.1 OAuth2 Grant Types Supported

| Grant Type         | Use Case                                      |
|--------------------|-----------------------------------------------|
| `client_credentials` | Service-to-service (M2M) auth                |
| `authorization_code` + PKCE | User login via SPA/UI                 |
| `refresh_token`    | Token renewal without re-auth                 |

### 2.2 Authentication Flow (Authorization Code + PKCE)

```
┌──────┐    1. GET /authorize      ┌────────────┐
│ Client│ ──────────────────────► │  SecureGate │
│ (SPA) │                         │  /authorize │
└──────┘    2. 302 → IdP login    └──────┬─────┘
            ◄───────────────────────────┘
┌──────┐    3. POST /token          ┌────────────┐
│ Client│ ──────────────────────► │  SecureGate │
│      │  (code + code_verifier)  │  /token     │
└──────┘                         └──────┬─────┘
            4. { access_token, refresh_token, id_token }
            ◄───────────────────────────┘
```

### 2.3 M2M Flow (Client Credentials)

```
┌────────────┐  POST /token              ┌────────────┐
│ Service X  │ ───────────────────────► │  SecureGate │
│            │  grant_type=client_      │  validates  │
│            │  credentials             │  client_id  │
└────────────┘                          └──────┬─────┘
              { access_token (scoped, short-lived) }
              ◄───────────────────────────┘
```

### 2.4 Token Format (JWT Claims)

```json
{
  "iss": "securegate",
  "sub": "user:uuid | service:client_id",
  "aud": ["metrics-ingest", "pulsealert"],
  "exp": 1719000000,
  "iat": 1718996400,
  "jti": "unique-token-id",
  "scope": "metrics:read alerts:write",
  "roles": ["editor"],
  "org_id": "org-abc123",
  "tenant_id": "tenant-xyz"
}
```

---

## 3. Token Lifecycle

| Parameter              | Access Token | Refresh Token | API Key     |
|------------------------|-------------|---------------|-------------|
| Lifetime               | 15 min      | 24 hours      | 90 days     |
| Storage (server)       | Redis (jti set, TTL=exp) | Redis (hashed, TTL) | Vault/DB (hashed) |
| Revocation             | Add jti to revocation list | Delete from Redis | Set `revoked_at` |
| Rotation               | New pair on refresh; old AT grace=30s | Single-use; rotated on each refresh | Manual or auto-rotate at expiry-7d |
| Signing Algorithm      | RS256 (asymmetric, key rotate quarterly) | — | — |

### 3.1 Token Revocation Flow

1. Client calls `POST /revoke` with token or jti.
2. Gateway adds `jti` to Redis revocation set with TTL = remaining token lifetime.
3. On every request, gateway checks `jti ∉ revocation_set` before authorizing.

---

## 4. RBAC Permission Model

### 4.1 Role Definitions

| Role          | Scope            | Permissions                                               |
|---------------|------------------|-----------------------------------------------------------|
| `super_admin` | Global           | `*:*` (all services, all actions)                         |
| `org_admin`   | Organization     | `org:manage`, all service perms within org                |
| `editor`      | Organization     | `metrics:read`, `metrics:write`, `alerts:read`, `alerts:write`, `status:read`, `status:write` |
| `viewer`      | Organization     | `metrics:read`, `alerts:read`, `status:read`              |
| `service`     | Cross-service    | Scoped via `aud` + `scope` claim; no org-level actions    |
| `api_key`     | As assigned      | Scoped to key's `allowed_scopes` at creation              |

### 4.2 Permission Format

`{service}:{action}` — examples:
- `metrics:read`, `metrics:write`
- `alerts:read`, `alerts:write`, `alerts:execute`
- `status:read`, `status:write`

### 4.3 Authorization Algorithm

```
1. Extract roles[] and scope from JWT.
2. Resolve permission set = UNION of permissions for each role.
3. Intersect with scope claim (refine, never expand).
4. Check: required_permission ∈ resolved_permissions.
5. If fail → 403 Forbidden with WWW-Authenticate header.
```

### 4.4 Service-Level Access Matrix

| Service          | viewer | editor | org_admin | super_admin |
|------------------|--------|--------|-----------|-------------|
| metrics-ingest   | READ   | WRITE  | WRITE     | WRITE       |
| pulsealert       | READ   | WRITE  | WRITE     | WRITE       |
| statushub        | READ   | WRITE  | WRITE     | WRITE       |
| securegate-admin | —      | —      | READ      | WRITE       |

---

## 5. API Key Management

### 5.1 API Key Structure

- Prefix: `sg_live_` or `sg_test_` + 32-byte random (base62).
- Stored: SHA-256 hash in DB; prefix stored in cleartext for lookup.
- Metadata: `org_id`, `allowed_scopes[]`, `expires_at`, `created_by`, `rotated_from`.

### 5.2 API Key Endpoints

| Method | Path                     | Auth        | Description              |
|--------|--------------------------|-------------|--------------------------|
| POST   | `/api-keys`              | JWT (admin) | Create new API key       |
| GET    | `/api-keys`              | JWT (admin) | List keys (masked)       |
| DELETE | `/api-keys/{id}`         | JWT (admin) | Revoke key               |
| POST   | `/api-keys/{id}/rotate`  | JWT (admin) | Rotate (old key grace=1h)|

API key auth: client sends `X-API-Key: sg_live_...`. Gateway hashes it, looks up in DB, checks expiry + scopes.

---

## 6. Rate Limiting Strategy

### 6.1 Tiers & Limits

| Tier        | Key                   | Limit          | Window   |
|-------------|-----------------------|----------------|----------|
| Anonymous   | IP                    | 20 req/min     | Sliding  |
| Authenticated| `org_id:user_id`     | 300 req/min    | Sliding  |
| Service (M2M)| `client_id`         | 1000 req/min   | Sliding  |
| API Key     | `api_key_id`          | 500 req/min    | Sliding  |
| Burst       | Per key (all tiers)   | 2× steady rate | 10s      |

### 6.2 Implementation

- **Algorithm**: Sliding window counter via Redis sorted sets (ZADD with timestamp score, ZREMRANGEBYSCORE, ZCARD).
- **Headers**: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`.
- **429 Response**: `{"error":"rate_limit_exceeded","retry_after":12}` with `Retry-After` header.
- **Per-service overrides**: Configurable per service (e.g., metrics-ingest: 600 req/min for editors).

### 6.3 Priority

Rate limit check occurs **after** authentication but **before** RBAC check. Authenticated rate limits always supersede anonymous limits.

---

## 7. API Contracts

### 7.1 Gateway Endpoints

#### `POST /oauth/token`
```
Request:
  grant_type: "authorization_code" | "client_credentials" | "refresh_token"
  code?: string (auth code)
  code_verifier?: string (PKCE)
  redirect_uri?: string
  client_id: string
  client_secret?: string
  refresh_token?: string
  scope?: string

Response 200:
  access_token: string (JWT)
  token_type: "Bearer"
  expires_in: 900
  refresh_token?: string
  scope: string

Response 401: { error: "invalid_client" | "invalid_grant", error_description: string }
```

#### `POST /oauth/revoke`
```
Request:
  token: string
  token_type_hint?: "access_token" | "refresh_token"

Response 200: {} (always, per RFC 7009)
```

#### `GET /oauth/.well-known/openid-configuration`
Standard OIDC discovery document.

### 7.2 Gateway Proxy Behavior

All requests to `/{service}/**` are proxied:

```
1. Extract token from Authorization header OR X-API-Key header.
2. Validate: signature, expiry, revocation, issuer.
3. Rate limit check (per identity).
4. RBAC check: required_permission = f(service, HTTP method).
5. Inject headers: X-User-Id, X-Org-Id, X-Roles, X-Scopes, X-Request-Id.
6. Proxy to upstream service.
7. On 401/403 from upstream → return 502 (upstream auth misconfig).
```

Method-to-action mapping:
- GET/HEAD/OPTIONS → `read`
- POST/PUT/PATCH/DELETE → `write`

---

## 8. Threat Model

### 8.1 Threats & Mitigations

| # | Threat                        | Category     | Likelihood | Impact | Mitigation                                              |
|---|-------------------------------|-------------|------------|--------|---------------------------------------------------------|
| 1 | Stolen access token           | Auth bypass | Medium     | High   | Short TTL (15m), RS256 signing, jti revocation, HTTPS-only |
| 2 | Refresh token replay          | Replay      | Medium     | High   | Single-use refresh tokens; old RT invalidated on use    |
| 3 | API key leak in logs          | Data exposure| Medium    | Medium | Keys never logged; only prefix stored; mask in API responses |
| 4 | Brute-force token endpoint    | DoS         | High       | Medium | Per-IP rate limit (20/min anon); account lockout after 5 failures |
| 5 | Privilege escalation          | Authz bypass| Low        | Critical| Scope intersection (never expand); roles from DB, not token; regular audit |
| 6 | Compromised signing key       | Forgery     | Low        | Critical| HSM-backed key storage; quarterly rotation; kid in JWT header |
| 7 | Token sidejacking (MITM)      | Auth bypass | Low        | High   | TLS 1.3 required; HSTS; token bound to TLS session (DPoP future) |
| 8 | DDoS via legitimate accounts  | DoS         | Medium     | High   | Org-level rate limits; adaptive throttling; circuit breaker to upstream |
| 9 | Expired key still accepted    | Auth bypass | Low        | High   | TTL enforced in Redis; cron sweeps stale keys; no clock skew tolerance >30s |
| 10| SQL/NoSQL injection in auth   | Injection   | Low        | Critical| Parameterized queries; input validation; ORM usage       |

### 8.2 Security Invariants

1. **No token → no access** (except health endpoint).
2. **Scope never exceeds role permissions** (intersection rule).
3. **All tokens are revocable within 1 second** (Redis-backed).
4. **API keys are never stored in plaintext** (SHA-256 + salt).
5. **All inter-service traffic is mTLS** (in addition to JWT).
6. **Clock skew tolerance ≤ 30 seconds** across all services.
7. **Failed auth attempts are logged without PII** (no passwords or tokens in logs).

### 8.3 Audit Events

Every auth decision emits an event:
```json
{
  "timestamp": "2024-06-21T10:00:00Z",
  "event": "auth.decision",
  "result": "deny",
  "reason": "insufficient_scope",
  "subject": "user:abc",
  "service": "metrics-ingest",
  "required": "metrics:write",
  "granted": ["metrics:read"],
  "source_ip": "203.0.113.42",
  "request_id": "req-123"
}
```

---

## 9. Configuration Sketch

```yaml
securegate:
  jwt:
    issuer: securegate
    algorithm: RS256
    access_ttl: 900s
    refresh_ttl: 86400s
    signing_key_id: sg-key-2024-q2
  rbac:
    roles_file: /config/roles.yaml
    default_deny: true
  rate_limit:
    redis_url: redis://rate-limiter:6379/0
    default_tier: authenticated
    tiers:
      anonymous: { limit: 20, window: 60s }
      authenticated: { limit: 300, window: 60s }
      service: { limit: 1000, window: 60s }
  api_key:
    prefix_live: sg_live_
    prefix_test: sg_test_
    hash_algorithm: sha256
    default_ttl: 7776000s  # 90 days
```