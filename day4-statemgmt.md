# Day 4: Web Mechanics & State Management

Covers: the URL-to-DOM lifecycle, where authentication vs authorization live in code
(mapped to your real Flask `app.py`), and cookies vs signed cookies vs JWTs vs server
sessions (a side-by-side lab) — plus a code review of your Express/JWT auth, since
those three files arrived during this session.

**How this was checked:** every lab mission below (section 3) was run for real against
`state_lab.py` in a Linux sandbox; the output shown is actual output, not illustrative.
The Express findings (section 4) are from reading `auth.ts`, `auth.routes.ts` and
`env.ts` directly — I did not run your Express app (I don't have the rest of its files:
`database.ts`, `server.ts`, `types/index.ts`). Section 4 ends with a prompt for your IDE
agent to verify two of the findings against your *real, running* app, which I'll review.

---

## 1. The URL-to-DOM lifecycle

What happens between you hitting Enter on a URL and seeing the page, for an app like yours:

1. **DNS resolution** — the browser turns the hostname into an IP. (`127.0.0.1` skips this;
   it's a literal address, which is one reason local dev feels instant.)
2. **TCP handshake** — three packets (SYN, SYN-ACK, ACK) open a connection to the server's
   listening socket. This is the `time_connect` you measured with `curl -w` back in Day 3.
3. **TLS handshake** — HTTPS only. Negotiates encryption before any HTTP bytes move. Your
   lab and your local apps run plain HTTP, so this step is skipped — one reason `Secure`
   cookies (Day 3 finding) matter once you deploy.
4. **HTTP request sent** — method, path, headers, optional body. For a GET of `/dashboard`,
   this also carries whatever cookie or `Authorization` header the browser already has.
5. **Server-side routing and handler** — Flask (or Express) matches the path to a function.
   This is where `@login_required` / `authenticateToken` runs, *before* any page content is built.
6. **Response** — status line, headers (`Set-Cookie`, `Content-Type`, ...), body.
7. **Browser parses HTML** — builds the DOM top to bottom. A `<script>` tag pauses parsing
   unless marked `async`/`defer`.
8. **CSSOM + render tree + layout + paint** — styles are combined with the DOM, positions and
   sizes are computed, pixels are drawn.
9. **JavaScript runs** — can now read the DOM, attach event listeners, make further requests
   (this is where a SPA's `fetch('/api/data', {headers:{Authorization: ...}})` happens, and where
   `document.cookie` would read a cookie — unless it's `HttpOnly`, which is exactly what that
   flag blocks).

**The one line to remember:** steps 1-6 happen on *every* full page load and every API call.
Step 5 (routing + the auth check) happens *before* the server does any work for that request.
That's why `@login_required` / `authenticateToken` sits at the very top of a route, not the bottom.

---

## 2. Authentication vs authorization, in your actual code

**Authentication** = "who are you?" (do you have a valid session/token at all)
**Authorization** = "are you allowed to do *this*?" (does your role/ownership permit this action)

### In your Flask app (`app.py`)

| Line(s) | What it does | AuthN or AuthZ? |
|---|---|---|
| L68-76 `login_required` | No `user_id` in session -> redirect/401. Doesn't look at *what* you're asking for, only *whether you're logged in at all*. | **Authentication** |
| L178-183, L200-203 | `INSERT ... (user_id, ...)` / `SELECT ... WHERE user_id = ?` using `session["user_id"]` | **Authorization** (the query itself decides you can only touch your own rows) |
| L237, L264-274 (profile) | Same pattern: identity from the session, query scoped to that id | **Authorization** |
| *Nowhere in this file* | A role check (`if user.role == "admin"`) | **There is no role-based authorization in this app.** Every logged-in user is equal. `/api/data` (L310-327) returns *everyone's* username list to *any* logged-in user — that's a Day 5 finding (excess data exposure), not a bug in the authZ pattern itself, since there's no "admin-only" concept to violate. |

The pattern to notice: authentication is one decorator, checked once per request. Authorization
is *distributed* — it's baked into every single query via `WHERE user_id = ?`. There's no
central "authorization layer" in this app; if a future route forgets the `WHERE` clause, that's
an IDOR, and no decorator catches it. This is exactly why Day 5 reviews every query individually.

### In your Express app (`auth.ts` / `auth.routes.ts`)

| Line(s) | What it does | AuthN or AuthZ? |
|---|---|---|
| `auth.ts` L19-27 | Reads a token from the `Authorization` header, or falls back to the `auth_token` cookie | gathering credentials |
| `auth.ts` L38 `jwt.verify(...)` | Checks the signature and expiry, sets `req.user` | **Authentication** |
| *Nowhere in these 3 files* | A role/permission check on `req.user` | **No authorization layer exists in what I can see.** `req.user` carries `userId` and `username` (from `TokenPayload` in `auth.routes.ts` L110-113) — no `role` field is even issued at login. If a route needs "admin only," there's currently nothing to check against. |

**Same gap, same lesson, in both of your apps:** authentication is handled centrally and well.
Authorization — deciding what a *specific, identified* user may do — doesn't exist as a general
mechanism in either codebase. It either has to be added (a role check, a resource-ownership
check) or, like your Flask app, baked individually into every query. Worth a line in your Day 5
report either way.

---

## 3. Cookies vs signed cookies vs JWT: a side-by-side lab

`day4-lab/state_lab.py` runs the same login/me/admin/logout cycle three ways on one server, so
you can compare mechanics directly instead of by description.

```
python state_lab.py      # http://127.0.0.1:5060
```

| Route prefix | Mechanism | Where the data lives |
|---|---|---|
| `/session/*` | server-side session | **on the server**, a random id in the cookie points to it |
| `/cookie/*` | Flask signed-cookie session | **in the cookie itself**, tamper-proof but readable |
| `/jwt/*` | JWT bearer token | **in the token**, client sends it in an `Authorization` header |

### Mission 1 — what each login actually hands you back (ran)

```
-- A server-side session (opaque cookie id):
   cookie sid = zlCKfRUPlMzAkXo5IZl0sU9KN4F3RshsALmprPQXxCs        <- random, means nothing on its own

-- B signed-cookie session (data lives in the cookie itself):
   cookie session = eyJyb2xlIjoidXNlciIsInVzZXIiOiJsYWItdXNlciJ9.awAhow.-7ZlQo--...

-- C JWT (bearer token):
   token = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJsYWItdXNlciIsInJvbGUiO...
   decoded header: {'alg': 'HS256', 'typ': 'JWT'}
   decoded payload: {'sub': 'lab-user', 'role': 'user', 'iat': 1795170723, 'exp': 1795171023}
```
Decoding the JWT needed **no secret at all** — just base64. **Signed is not encrypted.** Never
put anything secret (a password, a full card number) inside a JWT payload; anyone holding the
token can read it. The signature only stops *tampering*, not *reading*.

### Mission 2 — authentication (401) vs authorization (403), same test, all three (ran)

```
                 no creds   logged in as lab-user   logged in as lab-admin
session           401              403                    200
cookie            401              403                    200
jwt               401              403                    200
```
401 = "I don't know who you are" (authentication fails). 403 = "I know exactly who you are,
and the answer is no" (authentication succeeds, authorization fails). Mixing these two up in
an error message is itself a minor info-leak (telling an anonymous user "forbidden" instead of
"log in" confirms a protected resource exists there).

### Mission 3 — what does "logout" actually revoke? (ran — this is the core lesson)

```
-- server-side session: replay the OLD cookie after logout -> 401   (server deleted its record: dead)
-- signed-cookie session: replay the SAVED cookie after logout -> 200   (server held no record to delete: still valid!)
-- JWT: replay the SAVED token after "logout" -> 200   (no server record ever existed: still valid until exp!)
```
This is the single most important fact about stateless auth: **if the server never stored
anything, "logout" can only ask the browser to forget. A saved copy of the cookie or token
keeps working until it expires.** A server-side session can be killed instantly because the
server holds the one copy that matters. A JWT or signed cookie cannot be revoked early without
adding a server-side blocklist — which brings back the thing JWTs were meant to avoid.

### Mission 4 — tamper detection (ran)

```
-- tampered signed cookie (1 char flipped)      -> 401
-- tampered JWT signature (1 char flipped)       -> 401
-- JWT payload edited role: user -> admin, OLD signature kept -> 401
```
Both mechanisms correctly reject any edit, because the signature covers the *entire* header+payload.
You can't change one field and keep the old signature — which is exactly why forging a valid
token *without* knowing the secret is infeasible. (Forging one *with* the secret is section 4.)

### Mission 5 — expiry (ran, `LAB_JWT_TTL=3`)

```
fresh token  -> 200
... wait 4s ...
same token   -> 401
```

### Mission 6 — garbage input must not crash the server (ran)

```
Authorization: "Bearer not.a.jwt"  -> 401
Authorization: "Bearer "           -> 401
Authorization: "NotBearer xyz"     -> 401
(no header at all)                 -> 401
```
All 401, never a 500. This matters because your Day 2 review already found places (register,
login, dashboard) where malformed JSON produced a crash instead of a clean error — the same
discipline applies to auth headers.

---

## 4. Express/JWT code review (`auth.ts`, `auth.routes.ts`, `env.ts`)

### What's right
- Real passwords are hashed with `bcrypt` (10 salt rounds) — not hand-rolled, not plaintext.
- Login returns the **same error message** for "no such user" and "wrong password" (`auth.routes.ts` L92-106) — good, mirrors the Flask app.
- The cookie is set `httpOnly: true, sameSite: 'lax'`, and `secure` is tied to `NODE_ENV === 'production'` (`auth.routes.ts` L120-125) — that's the *correct pattern* (better than the Flask app, which doesn't set these at all), as long as `NODE_ENV` is genuinely `production` when deployed.
- Errors are caught and logged server-side; the client gets a generic 500 message, never a stack trace (`auth.routes.ts` L61-67, L137-143).
- `jwt.verify` throws on a bad signature or expired token, and that's handled (`auth.ts` L37-47) — matches mission 4/5 above.

### Finding 1 (High — read directly from the code, not a guess)
`env.ts` L9:
```ts
jwtSecret: process.env.JWT_SECRET || 'dev_secret_key_change_in_production_12345',
```
If `JWT_SECRET` is ever unset — a fresh clone, a misconfigured deploy, a `.env` that didn't
copy over — the app silently signs and verifies every token with this **fixed, literal string**.
Anyone who has seen this source file (which now includes anyone with read access to your
Day 1/Day 2 repos, past or present) can sign their *own* valid token for *any* `userId`/`username`
they want, using the real `jsonwebtoken` library and this exact string — no need to crack
anything, the key is just sitting there. Compare this to your Flask app's `SECRET_KEY`, which
at least falls back to `os.urandom(24).hex()` (random each start) rather than a fixed string.
**Action:** confirm `JWT_SECRET` is actually set to a long random value in your real `.env`
(never paste the value anywhere, including to me), and treat this fallback string as burned —
rotating it later doesn't un-expose code history. If this file was ever committed to a repo that
was public at any point (even briefly, like `cybrixaz-appsec-day3` before you fixed it), say so
in your Day 5 report.

### Finding 2 (Medium — read directly from the code)
`auth.routes.ts` L127-136 returns the raw JWT **in the JSON response body**, in addition to
setting it as an `httpOnly` cookie:
```ts
res.status(200).json({ success: true, message: 'Login successful.', token, user: {...} });
```
The entire point of `httpOnly` is that client-side JavaScript *cannot read the token*, so even
if a page has an XSS bug, the attacker's injected script can't steal the session. Handing the
same token back in the JSON body undoes that: any frontend code that does
`const data = await res.json(); localStorage.setItem('token', data.token)` (a very common pattern)
puts the token somewhere JavaScript — and therefore XSS — can read it. **If the frontend only
ever relies on the cookie and never reads `data.token`, this is a dead value with no effect;
if it's used, it quietly cancels out `httpOnly`.** Worth checking your frontend code for this.

### Finding 3 (Low — logic read from the code; ask your IDE agent to confirm with real timing)
`auth.routes.ts` L89-107: if `findUserByUsername` returns nothing, the function returns
immediately — `bcrypt.compare` is **never called**. If the user exists, `bcrypt.compare` always
runs (and bcrypt is deliberately slow). So a request for a real username takes measurably longer
than one for a made-up username, even though both return the same error text. This is the same
username-enumeration-by-timing pattern already in your Flask Day 2 findings (finding 6) — see the
verification prompt below.

### Finding 4 (Low — hardening suggestion, not a confirmed exploit)
`auth.ts` L38: `jwt.verify(token, config.jwtSecret)` passes no `algorithms` option. The
`jsonwebtoken` library is generally safe here with a plain string secret (it won't silently
accept `alg: "none"` or switch to an asymmetric algorithm), but explicitly pinning
`jwt.verify(token, config.jwtSecret, { algorithms: ['HS256'] })` is free, defense-in-depth, and
is what most security checklists ask for — it removes any doubt rather than relying on the
library's default behavior.

### Finding 5 (Info)
No `role` is issued in the JWT payload at all (`TokenPayload` only has `userId`/`username`),
and nothing in these 3 files checks one. I only have `auth.ts`, `auth.routes.ts`, `env.ts` — if
there's a separate `requireAdmin`/`requireRole` middleware elsewhere in `src/`, it isn't in what
you sent. Worth confirming either way for your Day 5 report (see the prompt below).

---

## 5. Verification prompt for your IDE agent

I can't run your Express app (I don't have `database.ts`, `server.ts`, `types/index.ts`, or a
Node runtime here). This checks findings 1, 3 and 5 against your *real, running* app, on your
own machine, on `127.0.0.1` only. I'll review whatever it reports back, the same way I reviewed
the Day 2 diff and pytest output.

```
Work only in day-2 (the Express app under src/). Do not touch Cybrixaz Work. Do not commit
anything from this check; it's read-only investigation. Stay on 127.0.0.1 only.

1. Check .env (do NOT print its contents or paste the value anywhere): does JWT_SECRET exist
   and is it set to something other than empty? Just answer yes/no, don't show me the value.

2. Search src/ for any role-based or permission check: requireRole, requireAdmin, req.user.role,
   isAdmin, permissions, rbac -- anything like that, in any file, not just the 3 I reviewed.
   Report what you find, or confirm there is none.

3. Start the Express app locally (host 127.0.0.1 only, confirm the port it's bound to before
   proceeding). Register two users via curl or an HTTP client: "timing-real" and don't register
   "timing-fake". Then time 10 login attempts for EACH against POST /api/auth/login with the
   WRONG password every time (same pattern as the Flask login-timing test from Day 2):
     - timing-real / any-wrong-password   (user exists, bcrypt.compare runs)
     - timing-fake / any-wrong-password   (user doesn't exist, bcrypt.compare never runs)
   Report the average response time in milliseconds for each group. Use a real timer
   (performance.now() in Node, or curl -w '%{time_total}\n'), not a guess.

4. Stop the server. Show me: the yes/no from step 1, the search results from step 2, and the
   two average timings from step 3.
```

---

## 6. Missions (do these yourself on the lab before moving on)

1. Run mission 1-6 yourself against `state_lab.py` and get the same status codes I did.
2. Start the lab with `LAB_JWT_SECRET=$(python -c "import secrets;print(secrets.token_hex(32))") python state_lab.py`, log in, and confirm the server now prints no weak-secret warning.
3. Log in via `/cookie/login`, then open the cookie value in `jwt_tool`-style decoding by hand: base64-decode the first segment (the Flask format is `payload.timestamp.signature`, dot-separated) and read the JSON. What's visible?
4. Pick one mission result and explain it to someone else in one sentence, no jargon.

## Explain-it-back questions
1. Why can a server-side session be killed instantly on logout, but a JWT can't?
2. What's the difference between what the *signature* protects and what *encryption* would protect? Which does a JWT have?
3. A route checks `if "user_id" in session`. Is that authentication or authorization? What would you add to make it check authorization too?
4. Why does returning a JWT in both a cookie and a JSON body partly defeat the purpose of `HttpOnly`?
5. If `JWT_SECRET` is never set in Express's `.env`, what exactly can an attacker do, and what do they need to know to do it?
6. In the URL-to-DOM lifecycle, which step runs the auth check, and why does that have to happen before the page is built?

## Day 4 report prompts
Done: which lab missions, which code review findings. Learned: one fact about revocation, one about signed-vs-encrypted. Blocked: anything Node/Express-specific you couldn't test. Next actions: Day 5 (attack your own app + the 1-page review) — findings 1-5 here plus your Flask findings from Day 2/3 are the raw material for it.
