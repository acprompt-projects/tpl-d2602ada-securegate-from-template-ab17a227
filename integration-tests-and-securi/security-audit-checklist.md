# Security Audit Checklist — SecureGate

## Authentication
- [ ] JWT tokens signed with RS256 or HS256 with ≥256-bit secret
- [ ] Token expiration enforced (access ≤15min, refresh ≤24h)
- [ ] Refresh token rotation on every use; old refresh token revoked
- [ ] Failed login rate-limited (≤5 attempts / 15min per IP)
- [ ] Passwords hashed with bcrypt (cost ≥12) or argon2id
- [ ] No credentials in URLs or logs

## Authorization (RBAC)
- [ ] Every endpoint enforces role check via middleware
- [ ] Admin-only routes return 404 or 403 for non-admin (no information leakage)
- [ ] Role hierarchy is one-directional; users cannot self-promote
- [ ] API key scopes are a subset of the creator's roles
- [ ] Service-to-service calls use separate service accounts

## Token Security
- [ ] Tampered tokens (modified payload/signature) rejected with 401
- [ ] Expired tokens rejected; no grace period beyond clock skew (≤30s)
- [ ] Revoked tokens checked against denylist/redis before acceptance
- [ ] Algorithm confusion attacks mitigated (explicit `alg` enforcement)
- [ ] JWT `jti` (token ID) used for per-token revocation tracking

## Rate Limiting
- [ ] Rate limits per-user (not just per-IP) using token identity
- [ ] 429 response includes `Retry-After` header
- [ ] Rate limit counters not bypassable via header spoofing (X-Forwarded-For stripped or trusted-proxy-only)
- [ ] Separate rate tiers: global, per-user, per-endpoint
- [ ] Burst allowance prevents slow-drip abuse

## API Key Management
- [ ] Keys hashed at rest (never stored plaintext)
- [ ] Key shown only once at creation time
- [ ] Key expiration enforced; unused keys auto-revoke after N days
- [ ] Key rotation supported without downtime
- [ ] Per-key rate limits independent of user token limits

## Penetration Checks (Automated in integration.test.js)
| Check | Status |
|---|---|
| Bad credentials → 401 | Covered |
| Token payload tampering → 401 | Covered |
| Expired/invalid token → 401 | Covered |
| Privilege escalation attempt → 403/404 | Covered |
| Invalid API key → 401 | Covered |
| Rate limit bypass → 429 triggered | Covered |
| Unauthenticated access → 401 | Covered |

## Infrastructure & Transport
- [ ] TLS 1.2+ enforced on all endpoints; HSTS header set
- [ ] CORS restricted to known origins
- [ ] Security headers: X-Content-Type-Options, X-Frame-Options, CSP
- [ ] No stack traces or internal IDs in error responses
- [ ] Secrets via env vars / vault; never in code or Docker images
- [ ] Dependency audit: `npm audit` / `snyk test` in CI pipeline
- [ ] Container runs as non-root user

## Logging & Monitoring
- [ ] Auth failures logged with IP, user agent, timestamp
- [ ] Token revocation events logged
- [ ] Rate limit threshold hits trigger alerts
- [ ] Audit log immutable and centralized
- [ ] No PII (tokens, passwords) in logs