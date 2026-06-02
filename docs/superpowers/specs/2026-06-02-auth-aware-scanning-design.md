# Auth-Aware Scanning — Design

**Date:** 2026-06-02
**Status:** Approved
**Phase:** #5 (Authenticated scanning)

## Problem

Every HTTP request the scanner makes is **stateless and anonymous**. Both the crawler
(`PageFetcher.fetch`) and the active/passive modules (`FormSubmitter.submit`,
`MissingSecurityHeadersModule`, etc.) call bare `Jsoup.connect(url)` with no shared
cookie jar. There is no session.

As a result the scanner can only see what an unauthenticated visitor sees. Targets that
gate their interesting surface behind a login (DVWA, most real apps) redirect the crawler
straight back to `/login`, so the bulk of pages — and the active-module findings they
would produce — are never reached.

"Auth-aware scanning" means: **establish a session once at scan start, then thread it
through every request** — crawler fetches *and* module probes alike — so the whole scan
runs as a logged-in user.

## Decisions

- **Mechanism: form login → cookie session, plus optional cookie injection.**
  The authenticator POSTs credentials to an HTML login form and captures the resulting
  session cookie(s) (DVWA-style: scrape the hidden CSRF `user_token` from the login page
  first). A user may instead paste an already-obtained session cookie to skip the login
  flow. **JSON/JWT bearer auth (Juice Shop SPA) is out of scope** — high effort, and SPA
  `/#/` routes are mostly invisible to our server-side crawler anyway.
- **Approaches considered:**
  - **(A) `AuthSession` value object threaded through `CrawlConfig` + `ScanContext`** —
    chosen. Immutable, explicit, anonymous scans pass an empty session and nothing
    changes.
  - **(B) A shared stateful JSoup session / cookie store reused across all requests** —
    rejected. JSoup has no clean shared mutable cookie store across the many independent
    `connect(...)` call sites; awkward and thread-unfriendly.
  - **(C) Cookie injection only (no login flow)** — rejected as the *sole* solution
    (doesn't deliver "the crawler logs in"), but folded into (A) as a supported input
    path because it is near-free and the most robust fallback for unusual login forms.
- **Credentials are never persisted.** `username`/`password` live in memory only, for the
  login step. The `Scan` entity records *that* it was authenticated (a boolean), never the
  password. Re-running requires re-entering credentials. Credentials are redacted from
  logs. This sidesteps secret-at-rest storage entirely.
- **Login failure fails the scan.** If login can't be verified, the scan is marked FAILED
  with a clear reason rather than silently falling back to an anonymous scan — a security
  tool that quietly scans logged-out would be misleading.
- **Don't self-logout.** An authenticated crawl will discover `/logout`; following it kills
  the session. The crawler skips URLs whose path matches a logout denylist.
- **No guided learning this phase** — Claude writes all code (user's explicit choice;
  overrides the `feedback-guided-learning` default for this feature).

## Architecture

### Session carrier — `com.lintsec.crawler.AuthSession`

Immutable record; the single thing passed around to make requests authenticated.

- `AuthSession(Map<String,String> cookies)`.
- `static AuthSession anonymous()` — empty cookies; today's behavior.
- `void applyTo(Connection conn)` — `conn.cookies(cookies)` (no-op when empty).
- Shaped so a future `Map<String,String> headers` (bearer tokens) can be added without
  touching call sites.

Lives in `crawler` because the scanner package already depends on `crawler`
(`CrawlResult`), and the crawler is the lower layer.

### Login config — `com.lintsec.crawler.LoginConfig`

Internal runtime record (compact-constructor guards, per project convention — not the web
DTO). Built by `ScanService` from the request DTO.

- `loginUrl`, `usernameField`, `passwordField`, `username`, `password`,
  `successCheck` (nullable), `sessionCookie` (nullable).
- When `sessionCookie` is present, the form-login fields are ignored.

### Authenticator — `com.lintsec.crawler.FormLoginAuthenticator`

`AuthSession authenticate(LoginConfig)` — runs **once**, before the crawl:

1. **Cookie-injection path:** if `sessionCookie` is set, parse it into a cookie map and
   return that `AuthSession` directly. (Skips steps 2–5.)
2. **GET the login page** (`loginUrl`) — `execute()`; keep `resp.cookies()` (initial
   session) and `resp.parse()` (the document).
3. **Scrape hidden fields** from the login form (CSRF tokens like DVWA `user_token`,
   preset hidden values) so they survive the round-trip.
4. **POST credentials** to the form action: `usernameField`→username,
   `passwordField`→password, plus scraped hidden fields; carry the initial cookies;
   `followRedirects(true)` (the session cookie often lands on the post-login redirect).
5. **Capture cookies** from the final response → the `AuthSession`.
6. **Verify success** (fail-safe, any of these ⇒ failure):
   - final status is 401/403, or
   - no session cookie was obtained, or
   - a non-blank `successCheck` substring is **absent** from the response body.

   On failure, throw an `AuthenticationException` carrying a human-readable reason.

### Threading the session

- **`CrawlConfig`** gains an `AuthSession authSession` field; `defaults()` →
  `AuthSession.anonymous()`. `PageFetcher.fetch` calls `config.authSession().applyTo(conn)`
  before `.get()`.
- **`ScanContext`** gains an `AuthSession authSession` field **and** a helper
  `Connection openConnection(String url)` that returns a `Jsoup` connection pre-configured
  with `userAgent`, `timeoutMs`, `ignoreContentType(true)`, `ignoreHttpErrors(true)`, and
  the auth cookies applied. Callers set method / data / `followRedirects` as needed.
  - `FormSubmitter.submit` and every module that currently hand-rolls `Jsoup.connect(url)`
    (the re-fetching passive modules — `MissingSecurityHeadersModule`,
    `CookieSecurityModule`, etc.) switch to `context.openConnection(url)`. This is the
    **single auth attach point** and removes duplicated connection boilerplate.

### Logout protection — `Crawler`

A constant denylist of path substrings (`logout`, `signout`, `sign-out`, `logoff`). During
link enqueue, skip any in-scope link whose path matches. Applied unconditionally (following
logout links is pointless even anonymously); cheap insurance for authenticated runs.

### Orchestration — `ScanService`

When the request carries auth config: map DTO → `LoginConfig` → `FormLoginAuthenticator
.authenticate(...)` → `AuthSession`. Inject it into both the `CrawlConfig` and the
`ScanContext` used for this scan, then crawl + scan as normal. An `AuthenticationException`
marks the scan FAILED with the reason (same path as other scan failures). On success, set
`Scan.authenticated = true`.

### Request DTO — `com.lintsec.dto.ScanCreateRequest`

Add an optional nested `AuthConfig auth` (`@Valid` cascade; `null` ⇒ anonymous, unchanged).

```
record AuthConfig(
    String loginUrl,        // http(s), required unless sessionCookie present
    String usernameField, String passwordField,
    String username, String password,
    String successCheck,    // optional
    String sessionCookie    // optional — present ⇒ skip form login
)
```

Conditional validation lives in a **compact constructor** (requiredness is conditional, so
field-level annotations don't fit cleanly): if `sessionCookie` is blank, then `loginUrl`,
`usernameField`, `passwordField`, `username`, `password` must all be non-blank, and
`loginUrl` must match `^https?://`.

### Entity + response

- `Scan` gains `boolean authenticated` (default false). Never stores credentials.
- `ScanResponse` mirrors the new field (per the "response DTOs don't auto-mirror entities"
  rule) so the UI can badge authenticated scans.

### Frontend (final step)

- **`NewScanPage`** — a collapsible "Authenticated scan" section (RHF + zod): login URL,
  username/password field names, username, password, optional success-check string, or a
  raw session-cookie field. Omitted ⇒ no `auth` in the request body.
- **types / `scanService`** — extend `CreateScanRequest` with the optional `auth` object.
- **`ScanResultsPage` / history** — small "Authenticated" badge when `scan.authenticated`.

  The backend is independently testable via the smoke script without any frontend change;
  the frontend form just makes it usable in the browser.

## Error handling

- **Login failure** (bad credentials, unreachable login URL, `successCheck` absent) →
  scan marked FAILED with the reason; no findings. Fail loud — auth is user-intent.
- **Mid-scan session expiry** → not handled in v1 (see Out of scope); findings simply
  degrade as requests start coming back logged-out.
- **Anonymous scans** → entirely unchanged; empty `AuthSession`, no new code paths taken.
- **Credential leakage** → credentials never logged, never persisted, never echoed in
  `ScanResponse`.

## Verification

- **`smoke-auth.sh`** (untracked, like the other smoke scripts), against **DVWA**:
  1. Authenticated scan (form login: `admin` / `password`, scraping `user_token`) reaches
     `/vulnerabilities/...` pages that an anonymous scan gets 302-redirected away from —
     assert higher visited-page count and/or findings only reachable behind login.
  2. Logout link is **not** followed (session survives the whole crawl).
  3. A deliberately wrong password → scan ends FAILED with a login-failure reason, no
     partial anonymous crawl.
  4. Cookie-injection path: paste a valid `PHPSESSID` → same authenticated reach as (1).
- **Frontend:** `npm run build`.

## Out of scope

- JSON/JWT bearer auth and SPA-aware crawling (Juice Shop).
- Mid-scan re-authentication / session-expiry recovery.
- Multi-step or MFA login flows; CAPTCHA.
- Persisting or encrypting credentials for scan re-runs.
- Per-request auth headers beyond cookies (the `AuthSession` shape leaves room, but no
  header support ships this phase).
