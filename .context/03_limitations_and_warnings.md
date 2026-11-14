# 03_limitations_and_warnings.md — Forensic Pitfalls, Rate Limits & Edge Warnings

## 1. Executive Summary

Automating Microsoft account recovery involves navigating aggressive web application firewalls (WAF), behavioral anti-fraud heuristics, Cross-Site Request Forgery (CSRF) defenses, and strict session-scoping rules. This document consolidates critical forensic discoveries from `report.md`, rate-limiting mechanics, and Discord integration boundaries that must be strictly respected.

---

## 2. Forensic Vulnerabilities & Implementation Traps

### 2.1 Cross-Domain Cookie Partitioning (`__Host-MSAAUTH`)
- **The Protocol Standard:**
  Per RFC 6265bis, cookies prefixed with `__Host-` are subject to strict browser-level security invariants:
  1. They must specify `Secure; HttpOnly`.
  2. They must set `Path=/`.
  3. They **MUST NOT** include a `Domain` attribute (they are strictly host-bound and cannot be shared across subdomains).
- **The Ktor Storage Bug:**
  In `Stage2Otp.kt`, successful OTP verification against `https://login.live.com/ppsecure/post.srf` yields `Set-Cookie: __Host-MSAAUTH=<token>`.
  Ktor's `AcceptAllCookiesStorage` scopes cookies strictly by the exact URI host of the request. Consequently, when subsequent stages (Stages 4 through 9) dispatch requests to `https://account.live.com`, Ktor's client **completely drops `__Host-MSAAUTH`**.
- **The Failure Symptom:**
  Although `Stage3Polish` captures Strong Authentication cookies (`AMRPSSecAuth` and `amsc`) under `account.live.com`, Microsoft's gateway periodically cross-checks the underlying live session. If `__Host-MSAAUTH` is missing, `account.live.com` returns an HTTP 302 redirect back to `login.live.com`, causing the bot to crash with `SessionExpiredException`.
- **The Verified Fix:**
  In `Stage2Otp.kt` (lines 132–135) and during Stage 8 client initialization, the engine explicitly duplicates `__Host-MSAAUTH` into `cookieStorage` under both domains:
  ```kotlin
  context.cookieStorage.addCookie(
      Url("https://login.live.com"),
      Cookie(name = "__Host-MSAAUTH", value = msaAuthCookie.value, domain = "login.live.com", path = "/", secure = true)
  )
  context.cookieStorage.addCookie(
      Url("https://account.live.com"),
      Cookie(name = "__Host-MSAAUTH", value = msaAuthCookie.value, domain = "account.live.com", path = "/", secure = true)
  )
  ```

---

### 2.2 The Stage 8 UAID Inversion Trap
- **The Invariant in `core.txt`:**
  In `core.txt` (line 768), the empirically verified HTTP request for adding an alias (`POST /AddAssocId`) specifies:
  - `uaid` MUST be transmitted in the `Cookie` header (`Cookie: ... uaid=...`).
  - `uaid` MUST **NEVER** be transmitted in the form body (`canary`, `PostOption`, `SingleDomain`, `UpSell`, `AddAssocIdOptions`, `AssociatedIdLive`).
- **The Historical Vulnerability:**
  Early versions of the codebase performed an exact inversion:
  1. An artificial 3-cookie whitelist (`__Host-MSAAUTH`, `AMRPSSecAuth`, `amsc`) actively stripped `uaid`, `MSPOK`, and `MSPRequ` from the outbound HTTP `Cookie` header.
  2. The form body explicitly injected `uaid = context.uaid`.
- **The Failure Symptom:**
  Microsoft WAF detects `uaid` inside the POST body while missing from ambient cookies. It identifies this signature as an unauthenticated CSRF injection and returns an HTTP 302 redirect to `https://login.microsoftonline.com`, terminating the session.
- **The Verified Fix:**
  In `Stage8Alias.kt` and `AliasClient.kt`, `uaid` is completely removed from the form payload, and the full ambient cookie jar (including `uaid`, `MSPOK`, and `MSPRequ` harvested from `login.live.com`) is attached to the request.

---

### 2.3 Redundant Canary Fetch Pitfall
- **The Defect:**
  In early iterations of Stage 8, before adding an alias, the bot attempted to refresh its CSRF token by dispatching an out-of-band `GET https://account.live.com/proofs/manage/additional` using an ad-hoc `HttpClient` that lacked the ambient cookie jar.
- **The Failure Symptom:**
  Because the client carried no session cookies, Microsoft responded with an immediate 302 redirect to `login.live.com`. The code interpreted this redirect as an expired session and aborted the workflow before `AddAssocId` was ever attempted.
- **The Verified Fix:**
  Removed the redundant GET call. Stage 8 directly reuses the active canary rotated out of Stage 6/7.

---

### 2.4 Stage 9 Null `passKeyId` Serialization
- **The Defect:**
  In `microsoft.recovery.model.SecurityCleanupRequest`, `val passKeyId: String? = null` represents an optional property used only when invoking `RemovePasskey`. When `encodeDefaults = true` was enabled in `MicrosoftHttpClientFactory`, serialization emitted:
  ```json
  {
    "uiflvr": 1001,
    "uaid": "...",
    "scid": 100109,
    "hpgid": 201030,
    "passKeyId": null
  }
  ```
- **The Failure Symptom:**
  Endpoints that do not accept passkeys (`DisableTfa`, `DeleteDevices`, `DeleteAppPassword`) strictly validate the JSON schema and reject payloads containing unexpected or null keys with HTTP 400 Bad Request or HTTP 500.
- **The Verified Fix:**
  Annotated `passKeyId` with `@EncodeDefault(EncodeDefault.Mode.NEVER)` in Kotlinx Serialization, ensuring the key is completely omitted from the JSON string when null.

---

### 2.5 Stage 6 `contactEmail` Risk Interstitial Trigger
- **The Defect:**
  In `POST /API/Recovery/RecoverUser`, passing a newly generated custom alias (e.g. `user@qhuyy.tech`) into `contactEmail` before that alias has been added or verified causes Microsoft's fraud detection system to trigger an interactive identity verification challenge.
- **The Verified Fix:**
  In `Stage6PasswordReset.kt`:
  ```kotlin
  val contactEmailForReset = if (newEmail.isNotBlank() && !newEmail.equals(context.originalEmail, ignoreCase = true)) {
      newEmail.trim()
  } else {
      "" // Empty string prevents challenge interstitials
  }
  ```

---

## 3. Microsoft Rate Limiting & Fraud Detection

### 3.1 `State: 201` and `State: 206` Soft Rate Limits
- **Endpoint:** `POST https://login.live.com/GetOneTimeCode.srf`
- **Mechanics:**
  When an operator requests an OTP multiple times in quick succession for the same account, Microsoft returns HTTP 200 with JSON:
  ```json
  {
    "State": 201,
    "FlowToken": "AQABAAAAAAD--...",
    "Error": null
  }
  ```
  - `State: 201`: High-frequency dispatch rate limit.
  - `State: 206`: Temporary cooldown period on the selected proof channel.
- **Crucial Rule:**
  **Do NOT throw an exception.** As long as `FlowToken` is non-null and non-blank, Microsoft has accepted the request and issued a valid continuation token. The engine logs a warning and continues with `postPpft = FlowToken`. If `FlowToken` is null or blank, only then does it fail.

---

### 3.2 `IfExistsResult: 5` Gate
- **Endpoint:** `POST https://login.live.com/GetCredentialType.srf`
- **Mechanics:**
  - `IfExistsResult: 0`: Valid existing account.
  - `IfExistsResult: 1`: Non-existent account.
  - `IfExistsResult: 5`: Account or IP address is throttled, or Arkose Labs FunCaptcha has been triggered.
- **Handling:**
  Headless HTTP automation cannot solve interactive Arkose captchas. When `IfExistsResult == 5`, `Stage1Discovery.kt` immediately halts and emits a descriptive failure: `"Account is throttled or captcha blocked (IfExistsResult=5)"`. The operator must wait or rotate the outbound proxy/IP.

---

### 3.3 Microsoft IP Blocks & Interstitials (Error 1247)
- **Symptoms:**
  When Microsoft flags the source IP address:
  1. `GET /login.srf` or `GET /ResetPassword.aspx` returns an HTML document titled `"Sign in to your Microsoft account"` with body text containing `"Protect your account"` or `"Verify your identity"`.
  2. `POST /API/Recovery/RecoverUser` returns JSON containing `"error": 1247`.
- **Handling:**
  `Stage3Parser` and `Stage6PasswordReset` inspect response HTML for keywords (`Protect`, `Verify`) and error code `1247`. The engine captures up to 500 characters of the diagnostic HTML and terminates the workflow with an explicit diagnostic recommendation to rotate the server's public IP.

---

### 3.4 Alias Quota Limits (Errors 1282 & 1213)
- **Mechanics:**
  Microsoft enforces strict account-level alias quotas:
  - Maximum of **2 primary alias changes per 7 days**.
  - Maximum lifetime quota of active aliases.
- **Symptoms:**
  - `MakePrimary` returns `Error 1282` when the 7-day limit is reached.
  - `AddAssocId` returns `Error 1213` when the alias addition quota is reached.
- **Safety Valve (`stopAfterStage7`):**
  If an operator knows the account has hit the 7-day alias limit, `RecoveryContext.stopAfterStage7 = true` allows running Stages 1 through 7 (resetting the password, generating a new recovery code, and suppressing alert emails) while safely bypassing Stages 8 and 9. The account is marked `SUCCESS` in the database with the original email preserved.

---

## 4. Discord Gateway Rate Limit Mitigations

### 4.1 The Multi-Stage Notification Problem
The recovery engine consists of 9 core stages, intermediate steps (`2b`), and debug dump stages (`3-debug`, `8-debug`). Emitting Discord messages, editing embeds, or updating components after every step rapidly exhausts Discord REST rate limits (HTTP 429), resulting in interaction timeouts and gateway thread exhaustion.

### 4.2 Modern Failure-Only Logging Architecture
Implemented in `RecoveryInteractionEvent.kt` and `DiscordLogger.kt`:

```
 Stage Success (1..9) ────► Local SLF4J Logger (logs/bot.log)
                                │ (No Discord API call)
 Debug Dumps (3/8)   ────► Buffered in Memory (AtomicReference)
                                │ (No Discord API call)
                                ▼
                           On Failure?
                                │
               ┌────────────────┴────────────────┐
               ▼                                 ▼
      First Failure Signal            Subsequent / Concurrent
   (failureEmitted = false)           (failureEmitted = true)
               │                                 │
               ▼                                 ▼
    failureEmitted.set(true)                Suppressed
    Post Single Detailed Embed               (No-Op)
    with Stage & Debug Dump
```

1. **Intermediate Success Suppression:**
   Stages 1 through 9 emit events to `StageListener`. All successful stage completions log strictly to local log files (`logs/bot.log`). Zero Discord messages are sent.
2. **In-Memory Debug Context Buffering:**
   Stages `3-debug` and `8-debug` pass raw HTML snippets and HTTP request parameters to `latestDebugContext = AtomicReference<String?>()`.
3. **Atomic Single-Failure Delivery:**
   `val failureEmitted = AtomicBoolean(false)`.
   When any stage fails:
   - `failureEmitted.compareAndSet(false, true)` ensures **exactly ONE** failure embed is sent to `logChannelId`.
   - The embed bundles the failed stage name, failure reason, and the buffered `latestDebugContext`.
   - Any subsequent errors (e.g. cleanup failures or retry storms) are suppressed.
4. **Final Result Embed:**
   Upon complete success across all 9 stages, **exactly ONE** rich credentials embed is dispatched to `notiChannelId`.

### 4.3 Discord Embed Field Truncation Rules
Discord rejects messages exceeding embed limits with HTTP 400 Bad Request. `DiscordLogger.kt` enforces safe boundaries:
- **Title:** Clamped to $\le 256$ characters.
- **Description:** Clamped to $\le 4096$ characters.
- **Field Name:** Clamped to $\le 256$ characters.
- **Field Value:** Clamped to $\le 1024$ characters (debug dumps exceeding 1024 chars are safely truncated with `...`).
- **Total Embed Characters:** Clamped to $\le 6000$ characters.
