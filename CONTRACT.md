# LintSec — Backend ↔ Frontend Contract

**Status**: living spec. Treat this as the source of truth for what the frontend can call. Endpoints not listed here don't exist yet. When a phase ships, update this doc in the same PR.

---

## 1. Conventions

| Topic | Value |
|---|---|
| Base URL (dev) | `http://localhost:8080` (frontend proxies `/api` → here) |
| Auth | HTTP-only session cookie `LINTSEC_SESSION`, Redis-backed |
| Frontend fetch | `credentials: 'include'` on every request |
| Content type | `application/json` (request + response) |
| Date format | ISO 8601 UTC string (`2026-05-12T14:30:00Z`) |
| IDs | `number` (Java `Long` ≤ 2^53 fits cleanly) |
| Empty body | `204 No Content` for delete; `200` with `{}` for ack |
| Errors | RFC 7807 `application/problem+json` — see §10 |
| Pagination | `?page=0&size=20&sort=createdAt,desc` → Spring `Page<T>` shape (§9.2) |
| CORS | dev only; configured to allow frontend dev origin with credentials |

**Phase markers**: each endpoint is tagged with the backend phase that will ship it. The frontend can stub against this doc before the endpoint exists.

---

## 2. Endpoint inventory

| Method | Path | Auth | Phase | Purpose |
|---|---|---|---|---|
| `POST` | `/api/auth/register` | no | 2 | Register with email+password |
| `POST` | `/api/auth/verify-email` | no | 2 | Confirm email with 6-digit code |
| `POST` | `/api/auth/resend-verification` | no | 2 | Re-send the verification code |
| `POST` | `/api/auth/login` | no | 2 | Email+password login; may return 2FA challenge |
| `POST` | `/api/auth/2fa/verify` | no | 2 | Complete login by submitting 6-digit code |
| `POST` | `/api/auth/2fa/enable` | yes | 2 | Turn on email 2FA for the current user |
| `POST` | `/api/auth/2fa/disable` | yes | 2 | Turn off email 2FA |
| `POST` | `/api/auth/logout` | yes | 2 | Invalidate session |
| `GET`  | `/oauth2/authorization/google` | no | 2 | Begin Google OAuth (Spring redirect) |
| `GET`  | `/api/me` | yes | 2 | Get current user |
| `POST` | `/api/scans` | yes | 5 | Start a new scan |
| `GET`  | `/api/scans` | yes | 5 | List my scans (paginated) |
| `GET`  | `/api/scans/{id}` | yes | 5 | Get one scan |
| `DELETE` | `/api/scans/{id}` | yes | 5 | Delete a scan |
| `GET`  | `/api/scans/{id}/pages` | yes | 5 | List pages crawled in a scan |
| `GET`  | `/api/scans/{id}/findings` | yes | 5 | List findings of a scan |
| `GET`  | `/api/scans/{id}/findings/{findingId}` | yes | 5 | One finding (includes AI explanation if ready) |
| `GET`  | `/api/scans/{id}/events` | yes | 6 | SSE progress stream |
| `GET`  | `/api/scans/{id}/report.pdf` | yes | 8 | Download PDF report |

Swagger UI: `http://localhost:8080/swagger-ui.html` (live once the backend is running).

---

## 3. Auth flows

### 3.1 Registration (LOCAL provider)

```
POST /api/auth/register
{ "email": "...", "password": "...", "displayName": "..." }
```

Validation: email is RFC-valid; password ≥ 10 chars, contains letter + digit; displayName 1–100 chars.

**Response 201**
```json
{ "userId": 42, "emailVerificationRequired": true }
```

The backend emails a 6-digit code. The user is **not** logged in yet; they must verify first.

### 3.2 Email verification

```
POST /api/auth/verify-email
{ "email": "...", "code": "123456" }
```

Codes are 6 digits, valid for 15 minutes, single-use. After 5 failed attempts the code is invalidated and a new one must be requested.

**Response 200**: empty body. The user is then auto-logged in (session cookie set) and the frontend should call `GET /api/me`.

### 3.3 Resend verification

```
POST /api/auth/resend-verification
{ "email": "..." }
```

Rate-limited to 1 per minute per email. **Response 200**: empty body.

### 3.4 Login

```
POST /api/auth/login
{ "email": "...", "password": "..." }
```

Three outcomes:

**A. No 2FA, success → 200, session cookie set**
```json
{ "twoFactorRequired": false, "user": { "...": "see UserDto" } }
```

**B. 2FA required → 200 (no session cookie yet)**
```json
{ "twoFactorRequired": true, "challengeId": "uuid-here" }
```
Frontend then prompts for a 6-digit code and calls `/api/auth/2fa/verify`.

**C. Wrong credentials → 401 ProblemDetail**

After 5 failed login attempts for an email within 15 minutes, returns 429 with a `retryAfterSeconds` field.

### 3.5 2FA verify

```
POST /api/auth/2fa/verify
{ "challengeId": "uuid-here", "code": "123456" }
```

**Response 200**: empty body, session cookie set. Frontend then calls `GET /api/me`.

### 3.6 Enable / disable 2FA

```
POST /api/auth/2fa/enable      (no body) → 200, sends confirmation code
POST /api/auth/2fa/confirm     { "code": "123456" } → 200 (2FA now active)
POST /api/auth/2fa/disable     { "password": "..." } → 200
```

(Confirm step prevents accidental enable. We'll wire this in Phase 2.)

### 3.7 Logout

```
POST /api/auth/logout
```

Invalidates the session. **Response 200**, empty body.

### 3.8 Google OAuth

Frontend triggers: `window.location.assign('/oauth2/authorization/google')`.

Spring handles the dance. On success, backend redirects to `http://localhost:5173/auth/callback` (configurable via `lintsec.frontend.base-url`) with the session cookie set. The callback page is expected to close itself (popup flow) and notify the opener, which then calls `GET /api/me`.

On first Google login the user is auto-created with `provider=GOOGLE`, `emailVerified=true`, no 2FA.

### 3.9 GET /api/me

**Response 200**
```json
{
  "id": 42,
  "email": "user@example.com",
  "displayName": "Jane",
  "provider": "LOCAL",          // LOCAL | GOOGLE
  "emailVerified": true,
  "twoFactorEnabled": false,
  "createdAt": "2026-05-12T14:30:00Z"
}
```

**Response 401** if no session.

---

## 4. Scans

### 4.1 Create scan

```
POST /api/scans
{
  "targetUrl": "https://example.com",
  "ownershipConfirmed": true
}
```

Validation:
- `targetUrl` must be `http://` or `https://`, ≤ 2048 chars, public DNS resolvable
- `ownershipConfirmed` **must** be `true` — otherwise 400

Rate limit: 5 concurrent RUNNING scans per user (returns 429 otherwise).

**Response 202**
```json
{
  "id": 17,
  "status": "PENDING",
  "targetUrl": "https://example.com",
  "createdAt": "2026-05-12T14:30:00Z"
}
```

The frontend should immediately open the SSE stream to watch progress.

### 4.2 List scans

```
GET /api/scans?page=0&size=20&sort=createdAt,desc
```

**Response 200**: paginated `ScanSummary` (see §9.4).

### 4.3 Get scan

```
GET /api/scans/{id}
```

**Response 200**: full `ScanDetail` (§9.5) — includes counts per severity and current progress.

**Response 404** if the scan doesn't belong to the caller.

### 4.4 Delete scan

```
DELETE /api/scans/{id}
```

Idempotent. **204 No Content**.

If the scan is currently RUNNING, the backend marks it cancelled and stops the executor; response is still 204.

### 4.5 List pages

```
GET /api/scans/{id}/pages?page=0&size=50
```

**Response 200**: paginated `ScanPageDto` (§9.6).

### 4.6 List findings

```
GET /api/scans/{id}/findings?severity=CRITICAL&page=0&size=50
```

Query params (all optional):
- `severity` — CRITICAL | HIGH | MEDIUM | LOW | INFO
- `type` — XSS | SQL_INJECTION | CORS | SECURITY_HEADERS | SENSITIVE_DATA
- `page`, `size`

**Response 200**: paginated `FindingSummary` (§9.7).

### 4.7 Get finding

```
GET /api/scans/{id}/findings/{findingId}
```

**Response 200**: `FindingDetail` (§9.8). If the AI explanation is not yet ready, `aiExplanation` is `null` and `aiStatus` is `"PENDING" | "FAILED"`.

---

## 5. SSE — `/api/scans/{id}/events`

Long-lived `text/event-stream`. The frontend opens it via `EventSource('/api/scans/17/events', { withCredentials: true })`.

Event types (the `event:` line of the SSE frame):

| event | data shape | when |
|---|---|---|
| `progress` | `{ phase: "CRAWLING" \| "SCANNING", percent: 0..100, pagesCrawled: number, totalPages: number, currentScanner?: string }` | every 500ms-ish during a scan |
| `page-crawled` | `ScanPageDto` (§9.6) | each time a page is added |
| `finding` | `FindingSummary` (§9.7) | each time a scanner files a finding |
| `ai-ready` | `{ findingId: number }` | when the AI explanation for a finding is written |
| `complete` | `ScanDetail` (§9.5) | scan finished successfully |
| `error` | `{ message: string }` | scan failed; the stream then closes |

The server sends `: heartbeat` comments every 15 s to keep proxies from killing the connection.

Reconnection: client should use `EventSource`'s built-in reconnect. Server respects `Last-Event-ID` so resumed streams don't re-deliver.

---

## 6. Report — `/api/scans/{id}/report.pdf`

```
GET /api/scans/{id}/report.pdf
```

**Response 200** with `Content-Type: application/pdf`, `Content-Disposition: attachment; filename="lintsec-scan-{id}.pdf"`.

**Response 409** if scan is not yet `COMPLETE`.

---

## 7. CSRF

Spring Security CSRF is enabled. On state-changing requests (POST/PUT/DELETE), the frontend must send the CSRF token.

- Token is delivered as the cookie `XSRF-TOKEN` (readable JS — not HTTP-only)
- Frontend reads it and echoes it in header `X-XSRF-TOKEN`
- The first GET to any endpoint mints the cookie

(Phase 2 will confirm/adjust this.)

---

## 8. CORS (dev)

Backend allows:
- Origin: `http://localhost:5173` (Vite default)
- `Access-Control-Allow-Credentials: true`
- Methods: GET, POST, PUT, DELETE, OPTIONS

Frontend must use `credentials: 'include'` (fetch) or `withCredentials: true` (axios / EventSource).

---

## 9. DTO reference

All DTOs are JSON. Fields not listed are not present. Unknown fields will be added in additive minor versions.

### 9.1 `UserDto` (`/api/me`)
```ts
{
  id: number,
  email: string,
  displayName: string | null,
  provider: "LOCAL" | "GOOGLE",
  emailVerified: boolean,
  twoFactorEnabled: boolean,
  createdAt: string  // ISO 8601
}
```

### 9.2 `Page<T>` (Spring shape, stripped to what the frontend uses)
```ts
{
  content: T[],
  totalElements: number,
  totalPages: number,
  number: number,   // current page (0-indexed)
  size: number,
  first: boolean,
  last: boolean
}
```

### 9.3 `CreateScanRequest`
```ts
{
  targetUrl: string,
  ownershipConfirmed: boolean
}
```

### 9.4 `ScanSummary` (list rows)
```ts
{
  id: number,
  targetUrl: string,
  status: "PENDING" | "RUNNING" | "COMPLETE" | "FAILED",
  createdAt: string,
  completedAt: string | null,
  pagesCrawled: number,
  findingsBySeverity: {
    CRITICAL: number, HIGH: number, MEDIUM: number, LOW: number, INFO: number
  }
}
```

### 9.5 `ScanDetail` (single scan)
```ts
{
  id: number,
  targetUrl: string,
  status: "PENDING" | "RUNNING" | "COMPLETE" | "FAILED",
  errorMessage: string | null,
  ownershipConfirmed: boolean,
  pagesCrawled: number,
  maxDepth: number,
  maxPages: number,
  requestDelayMs: number,
  startedAt: string | null,
  completedAt: string | null,
  createdAt: string,
  findingsBySeverity: { CRITICAL: number, HIGH: number, MEDIUM: number, LOW: number, INFO: number },
  durationMs: number | null
}
```

### 9.6 `ScanPageDto`
```ts
{
  id: number,
  url: string,
  statusCode: number | null,
  depth: number,
  title: string | null,
  crawledAt: string
}
```

### 9.7 `FindingSummary` (list rows)
```ts
{
  id: number,
  vulnerabilityType: "XSS" | "SQL_INJECTION" | "CORS" | "SECURITY_HEADERS" | "SENSITIVE_DATA",
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
  title: string,
  pageUrl: string | null,
  createdAt: string,
  aiStatus: "PENDING" | "READY" | "FAILED"
}
```

### 9.8 `FindingDetail`
```ts
{
  id: number,
  vulnerabilityType: "XSS" | "SQL_INJECTION" | "CORS" | "SECURITY_HEADERS" | "SENSITIVE_DATA",
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
  title: string,
  description: string | null,
  evidence: Record<string, unknown> | null,  // parsed from the backend's evidenceJson
  payloadRef: string | null,                 // e.g. "xss:0042" — never a raw payload
  page: ScanPageDto | null,
  aiStatus: "PENDING" | "READY" | "FAILED",
  aiExplanation: string | null,
  createdAt: string
}
```

---

## 10. Error format (RFC 7807)

All non-2xx responses use `application/problem+json`:

```json
{
  "type": "https://lintsec.local/errors/validation",
  "title": "Validation failed",
  "status": 400,
  "detail": "ownershipConfirmed must be true",
  "instance": "/api/scans",
  "errors": [
    { "field": "targetUrl", "message": "must be a valid http(s) URL" }
  ]
}
```

Common status codes:

| Status | When |
|---|---|
| 400 | Validation / malformed request |
| 401 | No session or session expired |
| 403 | Authenticated but not allowed (e.g. another user's scan) |
| 404 | Not found, or hidden behind ownership check (we don't leak existence) |
| 409 | State conflict (e.g. PDF requested before scan complete) |
| 429 | Rate-limited; body includes `retryAfterSeconds` |
| 500 | Unexpected — `detail` is generic, real cause in server logs |

The `errors[]` array is only present on 400 validation failures.

---

## 11. What's not yet implemented

Today (end of Phase 1) only the persistence layer exists. The endpoints above are the **planned contract**. The frontend can:

- Build all UI against this doc
- Mock responses using these shapes
- Wire actual fetches as each backend phase lands (Phase 2 → auth endpoints, Phase 5 → scan endpoints, Phase 6 → SSE, Phase 8 → PDF)

Any change to a shape after a phase ships requires a contract bump (note in §12).

---

## 12. Changelog

- **2026-05-13** — §3.8 OAuth2 success redirect target changed from `/` to `/auth/callback` (popup flow).
- **2026-05-12** — Initial draft (post-Phase 1).
