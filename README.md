# Day 4: Web Mechanics & State Management

A comprehensive hands-on lab exploring web authentication architecture, state management mechanics, token vs. cookie lifecycles, and a deep-dive security audit of Express/JWT authentication.

---

## Workspace Structure

```text
day-4/
├── day4-lab/
│   └── state_lab.py       # Standalone multi-state test server (127.0.0.1:5060, debug=False)
├── day4-statemgmt.md      # Lab curriculum and mission specifications
├── .gitignore             # Excludes .env, *.log, __pycache__, .venv, *.db
└── README.md              # Complete verification walkthrough and Day 4 report
```

---

## Part 1: State Lab Verification (Missions 1–6)

Executed against `day4-lab/state_lab.py` running on `http://127.0.0.1:5060`.

### Mission 1: Token & Cookie Structure Analysis
Compared what each authentication mechanism returns to the client upon successful login (`lab-user`):

* **A. Server-Side Session (`/session/login`)**:
  ```http
  Set-Cookie: sid=<redacted-opaque-32-byte-token>; Expires=...; Max-Age=3600; HttpOnly; Path=/; SameSite=Lax
  ```
  *Structure*: 32 bytes of cryptographically random urlsafe characters (256 bits of entropy). Contains no user data or claims; acts purely as an opaque pointer to server memory.
* **B. Signed Cookie Session (`/cookie/login`)**:
  ```http
  Set-Cookie: session=<redacted-payload>.<redacted-timestamp>.<redacted-hmac>; HttpOnly; Path=/; SameSite=Lax
  ```
  *Structure*: The first segment is base64url-encoded JSON: `{"role":"user","user":"lab-user"}`. The data is readable by anyone holding the cookie, but tamper-resistant due to the appended HMAC signature.
* **C. JWT Bearer Token (`/jwt/login`)**:
  ```json
  {
    "access_token": "<redacted-header>.<redacted-payload>.<redacted-signature>",
    "expires_in": 300,
    "token_type": "Bearer"
  }
  ```
  *Structure*:
  * *Header*: `{"alg":"HS256","typ":"JWT"}`
  * *Payload*: `{"sub":"lab-user","role":"user","iat":1795176009,"exp":1795176309}`
  * *Signature*: HMAC-SHA256 signature calculated over `header.payload`.
  * *Core Takeaway*: **Signed is not encrypted.** JWT claims are transmitted in plaintext base64url. Secrets or sensitive PII must never be stored in JWT payloads.

---

### Mission 2: Status Code Semantics (AuthN vs. AuthZ)
Evaluated route responses across unauthenticated requests, regular user credentials (`lab-user`), and administrative credentials (`lab-admin`):

| Mechanism | No Credentials (AuthN Check) | `lab-user` / role: `user` (AuthZ Check) | `lab-admin` / role: `admin` |
|---|:---:|:---:|:---:|
| **Server-Side Session (`/session/admin`)** | `401 Unauthorized` | `403 Forbidden` | `200 OK` |
| **Signed Cookie (`/cookie/admin`)** | `401 Unauthorized` | `403 Forbidden` | `200 OK` |
| **JWT Bearer (`/jwt/admin`)** | `401 Unauthorized` | `403 Forbidden` | `200 OK` |

* **401 Unauthorized**: Identity cannot be established (authentication missing or invalid).
* **403 Forbidden**: Identity is established, but the user lacks sufficient privileges/roles for the requested action (authorization failure).

---

### Mission 3: Session Revocation & Token Replay
Tested token replay resilience after calling the respective logout endpoints:

```text
-- Server-side session: before logout = 200, replay after logout = 401 (server deleted record)
-- Signed cookie:       before logout = 200, replay after logout = 200 (server holds no state)
-- JWT bearer token:    before logout = 200, replay after logout = 200 (token valid until exp)
```

* **Core Lesson**: Stateless authentication mechanisms (signed cookies and JWTs) cannot be revoked server-side on logout without introducing a server-side revocation blocklist or database session store. When a client "logs out", it merely drops its local copy; any intercepted token remains valid until `exp`. Server-side sessions can be terminated instantly by invalidating the server record.

---

### Mission 4: Cryptographic Tamper Detection
Tested server behavior when modifying token and cookie values:

```text
-- Tampered signed cookie (1 char flipped)              -> HTTP 401
-- Tampered JWT signature (1st char flipped)            -> HTTP 401
-- JWT payload edited role: user->admin (kept old sig)  -> HTTP 401
```

* Both signed cookies and JWTs strictly reject tampered payloads and signatures.
* *Cryptographic Observation*: In base64url encoding, flipping characters within significant data bits invalidates the HMAC comparison immediately.

---

### Mission 5: Token Expiration Enforcement (`LAB_JWT_TTL=3`)
Configured `state_lab.py` with a 3-second token lifespan (`LAB_JWT_TTL=3`) and tested temporal validation:

```text
Token generated with TTL: 3s
Fresh token access (immediate): HTTP 200
Waiting 4 seconds for expiration...
Expired token access:           HTTP 401 ({"error":"Not authenticated: no valid session or token."})
```

* Verified that `jwt_verify` evaluates `exp < time.time()` before honoring claims.

---

### Mission 6: Malformed Input Robustness
Submitted corrupt and non-standard payloads to ensure no unhandled exceptions trigger internal `500` server errors:

```text
GET /jwt/me with Bearer not.a.jwt        -> HTTP 401
GET /jwt/me with Bearer (empty)          -> HTTP 401
GET /jwt/me with NotBearer xyz           -> HTTP 401
GET /jwt/me without header               -> HTTP 401
GET /session/me with invalid sid         -> HTTP 401
GET /cookie/me with invalid cookie       -> HTTP 401
POST /jwt/login with bad JSON            -> HTTP 401
```

* All edge-case inputs resulted in clean `400` or `401` responses with zero server crashes.

---

## Part 2: Security Audit of Express / JWT (`day-2/src/`)

Audited `day-2/src/config/env.ts`, `day-2/src/middleware/auth.ts`, and `day-2/src/routes/auth.routes.ts`:

### 1. `JWT_SECRET` Fallback Vulnerability (`env.ts`)
* **Code Inspected** (`env.ts` line 9):
  ```typescript
  jwtSecret: process.env.JWT_SECRET || 'dev_secret_key_change_in_production_12345',
  ```
* **Security Impact**: If `JWT_SECRET` is unset in the deployment environment, the application falls back to a hardcoded, public string. Anyone with access to the repository history can forge administrative tokens for arbitrary user accounts.
* **Local Workspace Verification**: Confirmed that `day-2/.env` is configured with a secure 32-byte hex secret (`secrets.token_hex(32)`), preventing reliance on the fallback in local testing.

### 2. Dual Token Return & `HttpOnly` Neutralization (`auth.routes.ts`)
* **Code Inspected** (`auth.routes.ts` lines 120–136):
  ```typescript
  res.cookie('auth_token', token, { httpOnly: true, secure: config.nodeEnv === 'production', sameSite: 'lax' });
  res.status(200).json({ success: true, message: 'Login successful.', token, user: {...} });
  ```
* **Security Impact**: While setting `httpOnly: true` on cookies protects session tokens from JavaScript DOM access, returning the raw token in the JSON response body allows frontend applications to store it in `localStorage` or `sessionStorage`, negating XSS theft protections.

### 3. Username Enumeration via Timing Side-Channel (`auth.routes.ts`)
* **Code Inspected** (`auth.routes.ts` lines 89–107):
  ```typescript
  const user = findUserByUsername(trimmedUsername);
  if (!user) {
    return res.status(401).json({ error: 'Invalid username or password.' });
  }
  const isPasswordValid = await bcrypt.compare(String(password), user.password_hash);
  ```
* **Security Impact**: When a username does not exist, the route returns immediately without executing `bcrypt.compare`. When a user exists, `bcrypt.compare` runs 10 salt rounds (~80–150ms). Despite identical error strings, an attacker can measure response latency to enumerate valid usernames.
* **Remediation**: Run a dummy hash comparison (e.g. `bcrypt.compare(password, DUMMY_HASH)`) when the user lookup returns null to equalize execution timing.

### 4. Missing Algorithm Whitelist Pinning (`auth.ts`)
* **Code Inspected** (`auth.ts` line 38):
  ```typescript
  const decoded = jwt.verify(token, config.jwtSecret) as TokenPayload;
  ```
* **Security Impact**: `jwt.verify` is called without explicitly specifying `{ algorithms: ['HS256'] }`. Hardening standards recommend explicit algorithm pinning to prevent algorithm confusion attacks.

### 5. Absence of Role-Based Access Control (RBAC)
* **Code Inspected**: Searched `day-2/src/` for `role`, `admin`, `rbac`, or `permission` checks.
* **Finding**: Zero role or permission checks exist across the TypeScript routes and middleware. `TokenPayload` only contains `userId` and `username`. All authenticated users possess equal system privileges.

---

## Day 4 Submission Report

### 1. Done
* Extracted and organized the Day 4 workspace, establishing `.gitignore` boundaries.
* Successfully executed State Lab Missions 1–6 against `day4-lab/state_lab.py`, validating token structures, status codes, revocation behaviors, cryptographic tamper checks, token expiry, and malformed input handling.
* Completed a thorough static and behavioral security audit of `day-2/src/` (Express/JWT authentication), identifying hardcoded secret fallbacks, dual token return patterns, timing side-channels, and missing RBAC.

### 2. Learned
* **Token Visibility vs. Integrity**: Signed tokens (signed cookies and JWTs) provide integrity, not confidentiality. Header and payload data are fully readable via base64url decoding without possessing the secret key.
* **Stateless Revocation Cost**: Stateless JWTs cannot be revoked on logout without maintaining a server-side revocation list, re-introducing state into what was intended as a stateless architecture.
* **Timing Protections in Authentication**: Eliminating user enumeration requires constant-time execution paths; early returns on missing usernames allow side-channel enumeration even when error messages are identical.

### 3. Blocked
* **PowerShell String Parsing with External CLIs**: Direct inline JSON strings in PowerShell are susceptible to quote stripping by the Windows command parser. Bypassed by passing payloads via `@file.json` or utilizing Python test harnesses.
* **Base64url Padding Ambiguity**: Verified that flipping bits in the 43rd character of a base64url SHA-256 signature can alter non-significant padding bits; flipping leading or middle characters reliably triggers signature mismatch rejection.

### 4. Next actions
* Consolidate evidence from Day 2 (parameterization, IDOR), Day 3 (socket binds, security headers, cookie flags), and Day 4 (secret fallbacks, timing side-channels, stateless revocation) into the final **Day 5 Application Security Audit Report**.
* Prepare dynamic proof-of-concept tests and remediation patches for Day 5 attack scenarios.

---

## AI Assistance & Tooling Metadata

* **Primary AI Assistant**: Antigravity with Gemini (workspace execution, mission verification, and report synthesis).
* **Curriculum Design**: Claude chat for curriculum formulation and state lab architecture.
