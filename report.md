# Recovery Flow Inconsistency Report

## 1. Executive Summary

This report presents a forensic-grade comparative audit of the Microsoft Account Recovery & Security Maintenance engine (`microsoft.recovery` package) against the empirically verified HTTP protocol specification documented in `core.txt`. The audited codebase orchestrates a 9-stage automated lifecycle designed to recover and secure compromised Microsoft accounts—transitioning from initial credential discovery and proof dispatch, through session establishment and Strong Authentication (AMRP) cross-domain elevation, to emergency recovery code generation, password reset, notification suppression, alias rotation, and session revocation.

While the Kotlin implementation correctly handles complex low-level mechanics such as Unicode unescaping (`\u002b` $\to$ `+`) and soft rate-limiting states (`State: 201/206`), critical architectural flaws in session state propagation, cookie lifecycle scoping, and payload generation cause fatal failures during runtime execution. These systemic defects concentrate in **Stage 3 (Session Polish)** and **Stage 8 (Alias Rotation)**.

The audit identified critical discrepancies across five core dimensions:

1. **Session & Cookie Loss:**
   The codebase relies heavily on ad-hoc, isolated `HttpClient` instances created without Ktor's `HttpCookies` plugin (`Stage3Polish.kt`, `Stage8Alias.kt`, and `AliasClient.kt`). In Stage 8, an artificial 3-cookie whitelist (`__Host-MSAAUTH`, `AMRPSSecAuth`, `amsc`) actively strips essential session identifiers—specifically `uaid`, `MSPOK`, and `MSPRequ`—from HTTP `Cookie` headers. Furthermore, `__Host-MSAAUTH` is stored strictly under `login.live.com`, causing Ktor's `AcceptAllCookiesStorage` to drop it from automated requests targeting `account.live.com` (Stages 4 through 7).
2. **UAID Mismatch:**
   `RecoveryService.kt` initializes `context.uaid` with a synthetic random 32-character hexadecimal string instead of capturing the session-bound `uaid` cookie returned by Microsoft on the initial `login.srf` handshake. In Stage 8, the codebase strips `uaid` from the `Cookie` header while concurrently injecting it into the form body of `POST /AddAssocId`. Because `core.txt` mandates that `uaid` be transmitted exclusively in the `Cookie` header (and never in the `AddAssocId` form body), Microsoft's Risk Engine flags the transaction as an unauthenticated CSRF attempt and issues an immediate 302 redirect to OAuth login.
3. **Canary Rotation Desynchronization:**
   While canary rotation within the primary recovery steps is functional, Stage 8 attempts an out-of-band `GET /proofs/manage/additional` call to scrape a "fresh" canary using an isolated, cookie-stripped client. This unauthenticated call triggers an immediate 302 redirect to `login.microsoftonline.com`, terminating the stage with a `SessionExpiredException` before `AddAssocId` can even be dispatched.
4. **Redirect Handling Inconsistencies:**
   The global HTTP client configured in `MicrosoftHttpClientFactory.kt` enables automatic redirect following (`followRedirects = true`) across all methods without exception. In Stage 2b (`ppsecure/post.srf`), following 302 redirects automatically swallows intermediate response headers, preventing direct inspection of `Set-Cookie` headers if Ktor fails to register `__Host-MSAAUTH`. Conversely, Stage 8 inspects 302 redirects but fatally crashes when Microsoft redirects to authentication gateways due to stripped cookies.
5. **Payload Mismatches:**
   Critical form and JSON payloads diverge from the verified contract: `POST /AddAssocId` contains an extraneous `uaid` field and custom domain parameters (`qhuyy.tech` via an external OTC worker) instead of native `SingleDomain=outlook.com` with `AddAssocIdOptions=LIVE`; Stage 9 cleanup requests serialize `"passKeyId": null` due to `encodeDefaults = true`; and Stage 6 (`RecoverUser`) risks challenge interstitials by passing custom alias emails in `contactEmail` rather than the primary account email.

---

## 2. Session & Cookie Lifecycle Analysis

### 2.1 Storage Architecture and Cross-Domain Session Partitioning

The recovery engine initializes a single shared in-memory cookie storage (`AcceptAllCookiesStorage`) inside `RecoveryService.kt` (line 90):

```kotlin
val cookieStorage = AcceptAllCookiesStorage()
val client = MicrosoftHttpClientFactory.create(storage = cookieStorage)
```

In Ktor, `AcceptAllCookiesStorage` stores cookies scoped to the target URI's host and path. In a standard browser, cookies set by `.live.com` or explicitly forwarded across subdomains are accessible to both `login.live.com` and `account.live.com`. However, Ktor enforces strict URL-to-cookie matching. This creates severe cross-domain session partitioning:

#### 1. The `__Host-MSAAUTH` Partitioning Bug
In `Stage2Otp.kt` (lines 127–130), upon successful OTP submission to `https://login.live.com/ppsecure/post.srf`, the primary session token `__Host-MSAAUTH` is extracted and explicitly committed to the cookie jar:

```kotlin
context.cookieStorage.addCookie(
    Url("https://login.live.com"),
    Cookie(name = "__Host-MSAAUTH", value = msaAuthCookie.value, domain = "login.live.com", path = "/", secure = true),
)
```

Per RFC 6265bis, cookies prefixed with `__Host-` must be `Secure`, have `path=/`, and must **not** specify a `Domain` attribute (they are host-only). Because it is registered under `Url("https://login.live.com")`, any request executed by `context.httpClient` against `https://account.live.com`—such as Stage 4 (`GET /proofs/manage/additional`), Stage 5 (`POST /API/Proofs/GenerateRecoveryCode`), Stage 6 (`POST /API/Recovery/*`), and Stage 7 (`POST /API/Proofs/SetUserNotificationState`)—**completely omits `__Host-MSAAUTH`**. 

In `core.txt` (line 391), the verified HTTP request for Stage 4 explicitly includes:
```http
GET https://account.live.com/proofs/manage/additional
Cookie: AMRPSSecAuth=<amrp>; amsc=<amsc>; __Host-MSAAUTH=<host>
```
Omitting `__Host-MSAAUTH` on `account.live.com` requests leaves the session reliant solely on `AMRPSSecAuth`. If Microsoft's edge gateway re-verifies primary authentication, requests lacking `__Host-MSAAUTH` are challenged with an HTTP 302 redirect back to `login.live.com`.

#### 2. The `AMRPSSecAuth` and `amsc` Elevation Lifecycle
During Stage 3 (Session Polish), the bot exchanges the primary session token for an elevated Strong Authentication (`SA_20MIN`) session under `account.live.com`.
In `Stage3Polish.kt` (lines 292–313), `captureStage3AccountCookies` captures `Set-Cookie` headers from the redirect response of `POST https://account.live.com/proofs/Add?apt=2&wa=wsignin1.0`:

```kotlin
cookieStorage.addCookie(
    Url("https://account.live.com"),
    Cookie(name = "AMRPSSecAuth", value = value, domain = "account.live.com", path = "/", secure = true),
)
cookieStorage.addCookie(
    Url("https://account.live.com"),
    Cookie(name = "amsc", value = value, domain = "account.live.com", path = "/", secure = true),
)
```
These cookies are scoped strictly to `https://account.live.com`.

---

### 2.2 Stage 3 Cookie Loss via Unconfigured Isolated Clients

In `Stage3Polish.kt` (lines 50–60), the implementation attempts to bypass redirection loops by creating a standalone `isolatedClient`:

```kotlin
val isolatedClient = HttpClient(OkHttp.create()) {
    followRedirects = true
    install(HttpRedirect) { checkHttpMethod = false }
}
```

**Fatal Defect:** This client does **NOT** install the `HttpCookies` plugin!
1. When `isolatedClient.get(stabilizationUrl)` executes, only the manually concatenated header `cleanCookieHeader = "__Host-MSAAUTH=$msaAuthValue; uaid=$currentUaid"` is sent.
2. As the request navigates through intermediate redirect hops, any intermediate cookies returned via `Set-Cookie` are discarded because there is no cookie storage attached to the engine.
3. In `submitStage3AddProofForm` (lines 222–230), `noRedirectPostClient` is instantiated with `followRedirects = false` and **NO cookies attached whatsoever**. It submits `POST /proofs/Add?apt=2&wa=wsignin1.0` without forwarding any ambient cookies (`uaid`, `MSPOK`, `MSPRequ`, or `__Host-MSAAUTH`). While it manually captures `AMRPSSecAuth` from the 302 response, the incoming request violates the verified contract in `core.txt` (line 756), which passes the entire cookie jar (`-b /tmp/s1_cookies.txt`).

---

### 2.3 Stage 8 Isolated Client Creation & Whitelist Cookie Stripping

Stage 8 (`Stage8Alias.kt` and `AliasClient.kt`) exhibits the most destructive cookie handling in the entire codebase.

#### 1. Bare `HttpClient` Instantiation
In `Stage8Alias.kt` (lines 91–93) and `AliasClient.kt` (lines 112–119):
```kotlin
val noRedirectClient = HttpClient(client.engine) {
    followRedirects = false
}
```
This client has no `HttpCookies` plugin installed, completely isolating it from `context.cookieStorage`.

#### 2. Artificial 3-Cookie Whitelisting Drops Session Context
To populate the `Cookie` header for requests sent via `noRedirectClient`, `Stage8Alias.kt` (lines 309–338) and `AliasClient.kt` (lines 316–366) invoke `buildIsolatedAccountCookieHeader`:

```kotlin
val merged = linkedMapOf<String, Cookie>()
for (cookie in cookieStorage.get(Url("https://login.live.com"))) merged[cookie.name] = cookie
for (cookie in cookieStorage.get(Url("https://account.live.com"))) merged[cookie.name] = cookie

val requiredNames = listOf("__Host-MSAAUTH", "AMRPSSecAuth", "amsc")
val isolated = requiredNames.mapNotNull { name ->
    merged[name]?.takeIf { it.value.isNotBlank() }?.let { name to it.value }
}
return isolated.joinToString("; ") { (name, value) -> "$name=$value" }
```

**CRITICAL BUG:** The codebase explicitly filters all cookies in `cookieStorage` down to **exactly three names**: `__Host-MSAAUTH`, `AMRPSSecAuth`, and `amsc`.

Every other cookie present in the session storage is **completely stripped** from the HTTP request:
- **`uaid`:** Stripped from the `Cookie` header, despite being the cryptographic User-Agent binding for the session.
- **`MSPOK`:** Stripped from the `Cookie` header (session readiness flag).
- **`MSPRequ`:** Stripped from the `Cookie` header (login flow tracking).
- **`OParams`:** Stripped from the `Cookie` header (OAuth state token).

#### 3. Missing Cookie Inventory in Stage 8

| Cookie Name | Present in Storage? | Sent in Stage 8 Request Header? | Status / Impact |
|---|---|---|---|
| `__Host-MSAAUTH` | Yes | Yes (manually attached) | Transmitted |
| `AMRPSSecAuth` | Yes | Yes (manually attached) | Transmitted |
| `amsc` | Yes | Yes (manually attached) | Transmitted |
| `uaid` | Yes (under `login.live.com`) | **NO (STRIPPED)** | **FATAL:** Cookie missing while body parameter `uaid` is sent $\to$ CSRF/fraud trigger |
| `MSPOK` | Yes | **NO (STRIPPED)** | **HIGH:** Microsoft session gate fails handshake validation |
| `MSPRequ` | Yes | **NO (STRIPPED)** | **HIGH:** Request tracing context lost |
| `CkTst` | If set | **NO (STRIPPED)** | Cookie enablement test dropped |

#### 4. Failure to Persist Response Cookies
In `Stage8Alias.kt` (lines 188–224), `noRedirectClient.submitForm` posts to `https://account.live.com/AddAssocId`. Any `Set-Cookie` headers returned by Microsoft on this 302 response are **never saved** back into `context.cookieStorage`. When the code switches back to `client.post("https://account.live.com/API/MakePrimary")` (line 248) using `context.httpClient`, the client lacks the updated session state, causing subsequent calls to fail.

---

## 3. The UAID Problem

### 3.1 UAID Generation vs. Extraction Analysis

The User-Agent ID (`uaid`) is a 32-character hexadecimal string representing a unique client session instance within Microsoft's Identity and Risk Engine.

#### The `core.txt` Contract (Empirically Verified)
1. In Stage 1.1, the client sends `GET https://login.live.com/login.srf`. Microsoft's response sets the session `uaid` via an HTTP header:
   ```http
   Set-Cookie: uaid=a7c938f29d1045b8bc0192e4811a2f90; domain=login.live.com; path=/; Secure; HttpOnly
   ```
2. In the verified curl execution trace (`core.txt` lines 746–750):
   ```bash
   UAID=$(grep 'uaid' /tmp/s1_cookies.txt | awk '{print $7}')
   curl -s -b "__Host-MSAAUTH=${MSAAUTH}" -c /tmp/s1_cookies.txt \
     "https://login.live.com/login.srf?wa=wsignin1.0&...&wreply=https://account.live.com/proofs/Add?apt=2&uaid=${UAID}&lc=1033..."
   ```
   The `uaid` query parameter passed in the Stage 3 reply URL is **the exact `uaid` extracted from the Stage 1 cookie jar**.
3. In `core.txt` Section 3.4, the instruction states:
   > *"Tuyệt đối không hardcode `uaid` (như `9b699236...`). Phải generate ngẫu nhiên 32 ký tự hex cho mỗi session để tránh bị Microsoft Risk Engine gắn cờ."*
   
   This rule instructs the implementer not to use a fixed, hardcoded constant across different bot runs or accounts. However, once a session starts, **the session must remain bound to the `uaid` issued by Microsoft or synchronized throughout the cookie jar**.

#### The Kotlin Implementation Discrepancy
1. **Unsynchronized Random Generation:** In `RecoveryService.kt` (line 101):
   ```kotlin
   context = RecoveryContext(..., uaid = RecoveryParsers.generateUaid(), ...)
   ```
   `context.uaid` is initialized to a random 16-byte hex string before any network connection is made.
2. **Ignored Stage 1 Cookie:** In `Stage1Discovery.kt`, `GET login.srf` is called, and Microsoft returns a `Set-Cookie: uaid=<server_hex>`. `Stage1Discovery` never extracts this cookie and never updates `context.uaid`.
3. **Belated Stage 2 Sync:** In `Stage2Otp.kt` (lines 132–135), the code attempts to read `uaid` from `login.live.com` cookies and assign it to `context.uaid`. If this read fails or returns blank, `context.uaid` continues holding the mismatched synthetic string into downstream stages.

---

### 3.2 Why Stage 8 Fails: The UAID Inversion Trap

Stage 8 (`AddAssocId`) fails consistently with an HTTP 302 redirect to `https://login.microsoftonline.com` or `https://login.live.com`, causing `Stage8Alias.kt` (line 127) to throw:
```
SessionExpiredException: Session expired during Alias Rotation. Cannot add alias.
```

The failure is caused by an **inversion of the `uaid` contract**:

```
Expected Contract (core.txt):
  Cookie Header:  Cookie: AMRPSSecAuth=...; amsc=...; uaid=<session_uaid>; MSPOK=...
  POST Body:      canary=<canary>&PostOption=NONE&SingleDomain=outlook.com&AddAssocIdOptions=LIVE&AssociatedIdLive=<prefix>
  (uaid in Cookie: YES | uaid in POST Body: NO)

Actual Kotlin Implementation (Stage8Alias.kt & AliasClient.kt):
  Cookie Header:  Cookie: __Host-MSAAUTH=...; AMRPSSecAuth=...; amsc=...
  POST Body:      canary=<canary>&PostOption=NONE&SingleDomain=...&AssociatedIdLive=<prefix>&uaid=<cookie_uaid>
  (uaid in Cookie: NO  | uaid in POST Body: YES)
```

#### Detailed Failure Mechanics:
1. **Form Body Injection Anomaly:** In `Stage8Alias.kt` (lines 151–153) and `AliasClient.kt` (lines 134–136):
   ```kotlin
   if (actualCookieUaid != null) {
       add("uaid" to actualCookieUaid)
   }
   ```
   The code explicitly appends `"uaid"` to the form body parameters of `POST /AddAssocId`.
   In `core.txt` (lines 136, 566), the verified form body for `POST https://account.live.com/AddAssocId` contains **no `uaid` parameter**:
   `canary=<canary>&PostOption=NONE&SingleDomain=outlook.com&AddAssocIdOptions=LIVE&AssociatedIdLive=<new_prefix>`
2. **Cookie Header Stripping:** Concurrently, `buildIsolatedAccountCookieHeader` strips the `uaid` cookie from the HTTP `Cookie` header because `uaid` is not in `listOf("__Host-MSAAUTH", "AMRPSSecAuth", "amsc")`.
3. **Microsoft Anti-Fraud Detection:** Microsoft's WAF and Identity gatekeeper inspect incoming requests to `/AddAssocId`. When an endpoint receives a form parameter named `uaid`, it cross-references that value against the `uaid` present in the request's `Cookie` header.
   - When the `uaid` cookie is completely missing, the request is identified as an unauthenticated cross-site submission or session-hijacking attempt.
   - Microsoft immediately aborts the operation and returns an HTTP 302 redirecting to the login portal (`login.microsoftonline.com`).
4. **Premature Exception Trigger:** `Stage8Alias.kt` (lines 114–131) checks the 302 `Location` header, detects the redirect to `login.microsoftonline.com`, and throws `SessionExpiredException`, terminating the entire workflow.

---

## 4. Stage-by-Stage Discrepancy Table

The following table comprehensively compares the current Kotlin implementation against the verified specification in `core.txt` across all 9 stages and all 5 audit dimensions (Session & Cookie Loss, UAID Mismatch, Canary Rotation, Redirect Handling, and Payload Mismatches).

| Stage | API Endpoint | Expected Behavior/Params (core.txt) | Current Bug/Discrepancy (Kotlin Codebase) |
|---|---|---|---|
| **1** | `GET https://login.live.com/login.srf`<br>`POST https://login.live.com/GetCredentialType.srf` | **Expected:**<br>1. `GET /login.srf` returns HTTP 200 with cookies `uaid`, `MSPOK`, `MSPRequ` and HTML containing `ServerData.sFTAg`.<br>2. Extract session `uaid` cookie and `PPFT` flow token.<br>3. `POST /GetCredentialType.srf` with JSON: `{"username":"<email>","flowToken":"<PPFT>","isUcuxLoginForm":true,"checkPhones":true,"isCookieBannerShown":false}`.<br>4. Retain all cookies in jar. | **Discrepancy:**<br>1. **UAID Mismatch:** `context.uaid` is initialized to a random hex string in `RecoveryService.kt:101`. `Stage1Discovery.kt` completely ignores the `Set-Cookie: uaid` header returned by Microsoft, leaving `context.uaid` unsynchronized.<br>2. **Session / Cookie:** Client correctly sends `GetCredentialTypeRequest`, but cookies are not bound to an explicit session object outside Ktor's storage. |
| **2** | `POST https://login.live.com/GetOneTimeCode.srf`<br>`POST https://login.live.com/ppsecure/post.srf` | **Expected:**<br>1. `POST /GetOneTimeCode.srf` form body: `login=<email>&flowtoken=<PPFT>&purpose=eOTT_OtcLogin&channel=Email&AltEmailE=<proofId>`. If response returns `State: 201` or `206` but contains `FlowToken`, proceed without throwing.<br>2. `POST /ppsecure/post.srf` form body: `login=<email>&loginfmt=<email>&type=27&SentProofIDE=<proofId>&otc=<otp>&PPFT=<new_flow_token>&LoginOptions=3`.<br>3. Response yields `Set-Cookie: __Host-MSAAUTH=...; path=/; Secure; HttpOnly`. Intercept 302 response and persist master cookie. | **Discrepancy:**<br>1. **Redirect Handling:** In `MicrosoftHttpClientFactory.kt:34`, `followRedirects = true` causes Ktor to follow the 302 redirect from `ppsecure/post.srf` automatically. The intermediate 302 response headers are swallowed; `postResponse.headers` only contains final landing page headers.<br>2. **Session & Cookie Loss (Partitioning):** In `Stage2Otp.kt:127–130`, `__Host-MSAAUTH` is saved with `domain = "login.live.com"`. Because `__Host-` cookies are host-only, Ktor drops this cookie on all requests to `https://account.live.com` in Stages 4, 5, 6, 7. |
| **3** | `GET https://login.live.com/login.srf?wa=wsignin1.0&rpsnv=21&rver=7.5.2156.0&wp=SA_20MIN&wreply=https://account.live.com/proofs/Add?apt=2&uaid=<uaid>&lc=1033&id=38936&mkt=en-US`<br>`POST https://account.live.com/proofs/Add?apt=2&wa=wsignin1.0` | **Expected:**<br>1. `GET /login.srf?...` must send `Cookie: __Host-MSAAUTH=<msaauth>; uaid=<session_uaid>`. URL `wreply` parameter `uaid` must match `uaid` cookie.<br>2. Extracts hidden input `token_t` from HTML `<input name="t" value="...">` (length ~1024).<br>3. `POST /proofs/Add?apt=2&wa=wsignin1.0` sends form body `t=<token_t>` forwarding existing cookie jar.<br>4. Intercepts HTTP 302 redirect to capture `Set-Cookie: AMRPSSecAuth` and `amsc`. | **Discrepancy:**<br>1. **Session & Cookie Loss:** `Stage3Polish.kt:50–60` creates `isolatedClient` without `HttpCookies`. Intermediate redirect cookies are discarded.<br>2. **Session & Cookie Loss:** In `Stage3Polish.kt:222–243`, `submitStage3AddProofForm` creates `noRedirectPostClient` without `HttpCookies` and submits `t=<token_t>` with **NO incoming cookies attached**, violating the contract.<br>3. **UAID Mismatch:** If `storedUaid` was absent in Stage 2, `stabilizationUrl` embeds the random synthetic UAID rather than the true session UAID. |
| **4** | `GET https://account.live.com/proofs/manage/additional` | **Expected:**<br>1. Request headers: `X-Requested-With: XMLHttpRequest`, `Cookie: AMRPSSecAuth=<amrp>; amsc=<amsc>; __Host-MSAAUTH=<host>` (core.txt line 391).<br>2. Response: HTML (~230KB) containing `var t0 = {...}`.<br>3. Scrape `encryptedNetId` (len ~132) and initial `apiCanary` (len ~261). Decode Unicode escape sequences (`\u002b` $\to$ `+`, `\u003a` $\to$ `:`). | **Discrepancy:**<br>1. **Session & Cookie Loss:** In `Stage4Proofs.kt:26`, `context.httpClient` executes the GET request. Because `__Host-MSAAUTH` was scoped to `login.live.com`, Ktor's cookie jar sends ONLY `AMRPSSecAuth` and `amsc`, dropping `__Host-MSAAUTH`.<br>2. **Canary Rotation:** Correctly extracts initial canary and decodes Unicode. |
| **5** | `POST https://account.live.com/API/Proofs/GenerateRecoveryCode` | **Expected:**<br>1. Headers: `canary: <apiCanary>`, `Content-Type: application/json`, `x-ms-apiVersion: 2`, `x-ms-apiTransport: xhr`.<br>2. JSON payload: `{"encryptedNetId":"<encryptedNetId>"}`.<br>3. Response: `{"recoveryCode":"XXXXX-XXXXX-XXXXX-XXXXX-XXXXX","apiCanary":"<new_canary>"}`.<br>4. Update active canary with `apiCanary` from response body. | **Discrepancy:**<br>1. **Session & Cookie Loss:** Lacks `__Host-MSAAUTH` in automatic cookie jar.<br>2. **Canary Rotation:** Correctly updates `context.activeCanary` with `genCodeData.apiCanary`. Payload matches specification. |
| **6** | `GET https://account.live.com/ResetPassword.aspx?wreply=https://login.live.com/oauth20_authorize.srf&mn=<email>`<br>`POST https://account.live.com/API/Recovery/VerifyRecoveryCode`<br>`POST https://account.live.com/API/Recovery/RecoverUser` | **Expected:**<br>1. `GET /ResetPassword.aspx`: Scrape `sRecoveryToken` (len 562) and `RESET_CANARY` from `ServerData`.<br>2. `POST /API/Recovery/VerifyRecoveryCode`: Header `canary: <RESET_CANARY>`. JSON body: `{"publicKey":"2CBB...","recoveryCode":"<code>","code":"<code>","scid":100103,"token":"<sRecoveryToken>","uiflvr":1001}`. Response yields `verification_grant_token` (len ~6514) and rotated `apiCanary`.<br>3. `POST /API/Recovery/RecoverUser`: Header `canary: <rotated_canary>`. JSON body: `{"contactEmail":"<account_email>","contactEpid":"","password":"<new_password>","passwordExpiryEnabled":0,"publicKey":"2CBB...","token":"<verification_grant_token>"}`. | **Discrepancy:**<br>1. **Payload Mismatch:** In `Stage6PasswordReset.kt:138–140`, if `newEmail` is set, `contactEmailForReset` sends `newEmail` (or empty string) instead of the original target account email verified in `core.txt` line 838 (`contactEmail:$email`), risking challenge interstitials.<br>2. **Canary Rotation:** Canary chaining across `VerifyRecoveryCode` $\to$ `RecoverUser` is correctly implemented. |
| **7** | `POST https://account.live.com/API/Proofs/SetUserNotificationState` | **Expected:**<br>1. Headers: `canary: <apiCanary>`, `Content-Type: application/json`.<br>2. JSON payload: `{"proofDetails":[{"name":"<proofAddressOrPhone>","notificationEnabled":false,"type":"Email"}],"uiflvr":1001,"uaid":"<session_uaid>","scid":100109,"hpgid":201030}`.<br>3. Must iterate through all email and SMS proofs sequentially (never parallel).<br>4. Fail-closed: abort workflow if any suppression call fails. Rotate `apiCanary` from response body on each step. | **Discrepancy:**<br>1. **Session & Cookie Loss:** Redundant initial `GET /proofs/manage/additional` in `Stage7Suppression.kt:35` lacks `__Host-MSAAUTH`.<br>2. **Canary Rotation:** Correctly rotates canary per loop iteration (`canaryResponse.apiCanary`). Payload matches `core.txt`. |
| **8** | `GET https://account.live.com/proofs/manage/additional`<br>`POST https://account.live.com/AddAssocId`<br>`POST https://account.live.com/API/MakePrimary`<br>`POST https://account.live.com/names/manage` | **Expected:**<br>1. **NO redundant GET to `/manage/additional`!** Stage 8 must directly use the active canary from Stage 6/7.<br>2. `POST /AddAssocId`: Form body: `canary=<canary>&PostOption=NONE&SingleDomain=outlook.com&AddAssocIdOptions=LIVE&AssociatedIdLive=<alias_prefix>`.<br>   **NO `uaid` in form body!** Transmits full cookie jar (`AMRPSSecAuth`, `amsc`, `uaid`, `MSPOK`, `MSPRequ`). Creates native `@outlook.com` alias with **NO OTC verification required**.<br>3. `POST /API/MakePrimary`: Header `canary: <canary>`. JSON: `{"aliasName":"<new_email>","emailChecked":true,"removeOldPrimary":false,"uiflvr":1001,"uaid":"<session_uaid>","scid":100115,"hpgid":200650}`.<br>4. `POST /names/manage`: Form body: `canary=<canary>&action=RemoveAlias&aliasName=<old_email>&displayName=<old_email>`. Verifies confirmation string `"Note_AssociatedIdRemoved"`. | **CRITICAL MULTI-DIMENSIONAL FAILURE:**<br>1. **Session & Cookie Loss:** `Stage8Alias.kt:91` and `AliasClient.kt:112` instantiate a bare client without `HttpCookies`. `buildIsolatedAccountCookieHeader` strips `uaid`, `MSPOK`, `MSPRequ` from the `Cookie` header.<br>2. **UAID Mismatch:** `Stage8Alias.kt:152` and `AliasClient.kt:135` inject `uaid` into the form body of `AddAssocId`. The missing cookie + injected body parameter triggers Microsoft anti-fraud 302 redirect.<br>3. **Canary Rotation / Redundant GET:** Lines 98–136 execute a redundant `GET /manage/additional` under stripped cookies, causing an immediate 302 redirect and throwing `SessionExpiredException`.<br>4. **Payload Mismatch (Custom Domain):** `AliasClient.kt` deviates into a non-standard custom domain flow (`SingleDomain=qhuyy.tech`) requiring an external OTC polling worker and `/Aliases/Verify`, diverging completely from the native Outlook alias contract in `core.txt`.<br>5. **Cookie Persistence:** Response cookies from `AddAssocId` are not saved back into `context.cookieStorage`. |
| **9** | `POST https://account.live.com/API/Proofs/DisableTfa`<br>`POST https://account.live.com/API/Proofs/DeleteDevices`<br>`POST https://account.live.com/API/Proofs/DeleteAppPassword`<br>`POST https://account.live.com/API/Proofs/RemovePasskey` | **Expected:**<br>1. Headers: `canary: <apiCanary>`, `X-Requested-With: XMLHttpRequest`, `Content-Type: application/json`.<br>2. JSON payload for `DisableTfa`, `DeleteDevices`, `DeleteAppPassword`: `{"uiflvr":1001,"uaid":"<session_uaid>","scid":100109,"hpgid":201030}`.<br>3. JSON payload for `RemovePasskey`: adds `"passKeyId":"<id>"`.<br>4. Rotate `apiCanary` from each response sequentially. | **Discrepancy:**<br>1. **Payload Mismatch:** `SecurityCleanupRequest` has `val passKeyId: String? = null`. In `MicrosoftHttpClientFactory.kt:27`, `encodeDefaults = true` is configured. Consequently, JSON payloads for `DisableTfa`, `DeleteDevices`, and `DeleteAppPassword` serialize `"passKeyId": null`, which can trigger schema validation rejections on endpoints expecting only `{uiflvr, uaid, scid, hpgid}`.<br>2. **Canary Rotation:** Sequential rotation of `activeCanary` across all four endpoints is correctly implemented. |

---

## 5. Specific Code Fixes Required

This section provides concrete, production-ready code modifications for the top 3 most critical bugs discovered during the audit. Each fix includes the exact file paths, line numbers, rationale, before/after code blocks, and invalidation criteria.

---

### Bug 1: Stage 8 Isolated HttpClient Creation & Cookie Jar Stripping

#### Affected Files & Line Numbers:
- `src/main/kotlin/microsoft/recovery/stages/Stage8Alias.kt` (lines 91–137, 188–235, 309–340)
- `src/main/kotlin/microsoft/recovery/alias/AliasClient.kt` (lines 112–155, 316–366)

#### Problem Mechanism:
Stage 8 instantiates an unconfigured `HttpClient` without the `HttpCookies` plugin and uses an artificial whitelist (`listOf("__Host-MSAAUTH", "AMRPSSecAuth", "amsc")`) in `buildIsolatedAccountCookieHeader`. This actively strips `uaid`, `MSPOK`, `MSPRequ`, and all other session cookies from the request. Furthermore, it executes a redundant `GET /proofs/manage/additional` that fails under stripped cookies, throwing `SessionExpiredException`. Finally, any cookies returned in `Set-Cookie` by `POST /AddAssocId` are lost.

#### Actionable Fix:
1. Remove the redundant `GET /proofs/manage/additional` call. Use the valid `activeCanary` carried over from Stage 6 / Stage 7.
2. Bind the `noRedirectClient` directly to `context.cookieStorage` via `install(HttpCookies)`.
3. Eliminate the 3-cookie whitelist filter: ensure all session cookies from both `login.live.com` and `account.live.com` (especially `uaid`) are present.
4. Capture and store all `Set-Cookie` headers returned by `POST /AddAssocId` back into `context.cookieStorage`.

#### Code Replacement in `src/main/kotlin/microsoft/recovery/stages/Stage8Alias.kt`:

##### BEFORE (Lines 91–137):
```kotlin
            val noRedirectClient = HttpClient(client.engine) {
                followRedirects = false
            }

            val addAliasResult = runCatching {
                noRedirectClient.use { stageClient ->
                    val (refreshCookieHeader, _) = buildIsolatedAccountCookieHeader(cookieStorage, "GET /proofs/manage/additional")
                    val manageResponse = stageClient.get("https://account.live.com/proofs/manage/additional") {
                        header(HttpHeaders.UserAgent, MicrosoftHttpClientFactory.DEFAULT_USER_AGENT)
                        header(HttpHeaders.AcceptLanguage, "en-US,en;q=0.9")
                        if (refreshCookieHeader.isNotBlank()) {
                            header(HttpHeaders.Cookie, refreshCookieHeader)
                        }
                    }
                    for (rawHeader in manageResponse.headers.getAll(HttpHeaders.SetCookie).orEmpty()) {
                        val parsed = runCatching { parseServerSetCookieHeader(rawHeader) }.getOrNull()
                        if (parsed != null && parsed.name.isNotBlank()) {
                            cookieStorage.addCookie(
                                Url("https://account.live.com"),
                                parsed.copy(domain = parsed.domain ?: "account.live.com", path = parsed.path ?: "/"),
                            )
                        }
                    }
                    val manageLocation = manageResponse.headers[HttpHeaders.Location]
                    if ((manageResponse.status == HttpStatusCode.Found ||
                            manageResponse.status == HttpStatusCode.SeeOther ||
                            manageResponse.status == HttpStatusCode.TemporaryRedirect) &&
                        manageLocation != null &&
                        (manageLocation.contains("login.microsoftonline.com", ignoreCase = true) ||
                            manageLocation.contains("login.live.com", ignoreCase = true))
                    ) {
                        logger.error(
                            "Stage 8 GET /proofs/manage/additional {} redirect Location before SessionExpiredException: {}",
                            manageResponse.status.value,
                            manageLocation,
                        )
                        throw SessionExpiredException(
                            "Session expired during Alias Rotation. Cannot add alias.",
                            redirectLocation = manageLocation,
                        )
                    }
                    val manageHtml = runCatching { manageResponse.bodyAsText() }.getOrDefault("")
                    val freshCanary = RecoveryParsers.extractApiCanary(manageHtml, MicrosoftHttpClientFactory.json)
                    if (!freshCanary.isNullOrBlank()) {
                        activeCanary = freshCanary
                    }
```

##### AFTER (Fixed & Compliant with core.txt):
```kotlin
            // Install HttpCookies bound to the shared session storage; followRedirects = false for 302 inspection
            val noRedirectClient = HttpClient(client.engine) {
                followRedirects = false
                install(HttpCookies) {
                    this.storage = cookieStorage
                }
            }

            val addAliasResult = runCatching {
                noRedirectClient.use { stageClient ->
                    // Ensure login cookies (uaid, __Host-MSAAUTH) are mirrored to account.live.com in cookieStorage
                    val loginCookies = cookieStorage.get(Url("https://login.live.com"))
                    for (c in loginCookies) {
                        cookieStorage.addCookie(
                            Url("https://account.live.com"),
                            c.copy(domain = "account.live.com", path = "/"),
                        )
                    }

                    // Directly execute POST /AddAssocId using activeCanary (redundant GET removed)
```

##### BEFORE (`buildIsolatedAccountCookieHeader`, Lines 321–325):
```kotlin
        val requiredNames = listOf("__Host-MSAAUTH", "AMRPSSecAuth", "amsc")
        val isolated = requiredNames.mapNotNull { name ->
            merged[name]?.takeIf { it.value.isNotBlank() }?.let { name to it.value }
        }
```

##### AFTER (Preserve all session cookies):
```kotlin
        // Retain all session identifiers: uaid, MSPOK, MSPRequ, __Host-MSAAUTH, AMRPSSecAuth, amsc
        val isolated = merged.filter { (_, cookie) -> cookie.value.isNotBlank() }
            .map { (name, cookie) -> name to cookie.value }
```

---

### Bug 2: Stage 8 `AddAssocId` Payload Corruption (Injected `uaid` & Domain Parameter Mismatch)

#### Affected Files & Line Numbers:
- `src/main/kotlin/microsoft/recovery/stages/Stage8Alias.kt` (lines 144–155)
- `src/main/kotlin/microsoft/recovery/alias/AliasClient.kt` (lines 127–138)

#### Problem Mechanism:
`Stage8Alias.kt` and `AliasClient.kt` inject `"uaid" to actualCookieUaid` into the `application/x-www-form-urlencoded` body of `POST /AddAssocId`. In `core.txt` (lines 136, 566), `AddAssocId` strictly accepts:
`canary`, `PostOption`, `SingleDomain`, `UpSell`, `AddAssocIdOptions`, and `AssociatedIdLive`.
Injecting `uaid` into the form body when the cookie header is stripped or evaluated by Microsoft WAF causes an immediate CSRF rejection and 302 redirect. Furthermore, `SingleDomain` must be locked to `"outlook.com"` with `AddAssocIdOptions=LIVE`.

#### Actionable Fix:
Remove `uaid` entirely from the form parameters of `AddAssocId` in both files. Enforce `SingleDomain = "outlook.com"`, `AddAssocIdOptions = "LIVE"`, and pass only the username prefix in `AssociatedIdLive`.

#### Code Replacement in `src/main/kotlin/microsoft/recovery/stages/Stage8Alias.kt`:

##### BEFORE (Lines 144–154):
```kotlin
                    val formPairs = buildList {
                        add("canary" to activeCanary)
                        add("PostOption" to "NONE")
                        add("SingleDomain" to targetDomain)
                        add("UpSell" to "")
                        add("AddAssocIdOptions" to "LIVE")
                        add("AssociatedIdLive" to newAliasPrefix)
                        if (actualCookieUaid != null) {
                            add("uaid" to actualCookieUaid)
                        }
                    }
```

##### AFTER (Fixed & Compliant with core.txt):
```kotlin
                    // Form body strictly conforms to core.txt (NO uaid parameter)
                    val formPairs = listOf(
                        "canary" to activeCanary,
                        "PostOption" to "NONE",
                        "SingleDomain" to "outlook.com",
                        "UpSell" to "",
                        "AddAssocIdOptions" to "LIVE",
                        "AssociatedIdLive" to newAliasPrefix,
                    )
```

#### Code Replacement in `src/main/kotlin/microsoft/recovery/alias/AliasClient.kt`:

##### BEFORE (Lines 127–137):
```kotlin
            val formPairs = buildList {
                add("canary" to refreshedCanary)
                add("PostOption" to "NONE")
                add("SingleDomain" to aliasDomain)
                add("UpSell" to "")
                add("AddAssocIdOptions" to "LIVE")
                add("AssociatedIdLive" to aliasPrefix)
                if (refreshedCookieUaid != null) {
                    add("uaid" to refreshedCookieUaid)
                }
            }
```

##### AFTER (Fixed & Compliant with core.txt):
```kotlin
            val formPairs = listOf(
                "canary" to refreshedCanary,
                "PostOption" to "NONE",
                "SingleDomain" to "outlook.com",
                "UpSell" to "",
                "AddAssocIdOptions" to "LIVE",
                "AssociatedIdLive" to aliasPrefix,
            )
```

---

### Bug 3: Cross-Domain Session Partitioning of `__Host-MSAAUTH` in Stage 2 & Stage 3 Cookie Loss

#### Affected Files & Line Numbers:
- `src/main/kotlin/microsoft/recovery/stages/Stage2Otp.kt` (lines 115–136)
- `src/main/kotlin/microsoft/recovery/stages/Stage3Polish.kt` (lines 50–92, 222–251)

#### Problem Mechanism:
1. In `Stage2Otp.kt`, `__Host-MSAAUTH` is saved exclusively under `Url("https://login.live.com")`. Because Ktor partitions cookies strictly by URL host, subsequent automated requests to `https://account.live.com` (Stages 4–7) omit `__Host-MSAAUTH`.
2. In `Stage3Polish.kt`, `isolatedClient` and `noRedirectPostClient` do not install `HttpCookies`, losing all redirect cookies and submitting `POST /proofs/Add` with zero incoming cookies.

#### Actionable Fix:
1. When capturing `__Host-MSAAUTH` in `Stage2Otp.kt`, mirror the cookie in `cookieStorage` to `https://account.live.com` with `domain = "account.live.com"` so all future requests to `account.live.com` automatically include it.
2. Install `HttpCookies` bound to `context.cookieStorage` on both `isolatedClient` and `noRedirectPostClient` in `Stage3Polish.kt`.

#### Code Replacement in `src/main/kotlin/microsoft/recovery/stages/Stage2Otp.kt`:

##### BEFORE (Lines 126–131):
```kotlin
            } else {
                context.cookieStorage.addCookie(
                    Url("https://login.live.com"),
                    Cookie(name = "__Host-MSAAUTH", value = msaAuthCookie.value, domain = "login.live.com", path = "/", secure = true),
                )
```

##### AFTER (Bridge __Host-MSAAUTH across both login and account domains):
```kotlin
            } else {
                val msaAuthValue = msaAuthCookie.value
                context.cookieStorage.addCookie(
                    Url("https://login.live.com"),
                    Cookie(name = "__Host-MSAAUTH", value = msaAuthValue, domain = "login.live.com", path = "/", secure = true),
                )
                // Bridge to account.live.com to prevent cookie loss in Stages 4-7
                context.cookieStorage.addCookie(
                    Url("https://account.live.com"),
                    Cookie(name = "__Host-MSAAUTH", value = msaAuthValue, domain = "account.live.com", path = "/", secure = true),
                )
```

#### Code Replacement in `src/main/kotlin/microsoft/recovery/stages/Stage3Polish.kt`:

##### BEFORE (Lines 50–60):
```kotlin
            val isolatedClient = if (clientEngine != null) {
                HttpClient(clientEngine) {
                    followRedirects = true
                    install(HttpRedirect) { checkHttpMethod = false }
                }
            } else {
                HttpClient(OkHttp.create()) {
                    followRedirects = true
                    install(HttpRedirect) { checkHttpMethod = false }
                }
            }
```

##### AFTER (Install HttpCookies with shared cookie storage):
```kotlin
            val isolatedClient = HttpClient(clientEngine ?: OkHttp.create()) {
                followRedirects = true
                install(HttpRedirect) { checkHttpMethod = false }
                install(HttpCookies) {
                    this.storage = context.cookieStorage
                }
            }
```

##### BEFORE (Lines 222–230 in `submitStage3AddProofForm`):
```kotlin
        val noRedirectPostClient = if (clientEngine != null) {
            HttpClient(clientEngine) {
                followRedirects = false
            }
        } else {
            HttpClient(OkHttp.create()) {
                followRedirects = false
            }
        }
```

##### AFTER (Attach shared cookie storage so incoming session cookies are transmitted):
```kotlin
        val noRedirectPostClient = HttpClient(clientEngine ?: OkHttp.create()) {
            followRedirects = false
            install(HttpCookies) {
                this.storage = context.cookieStorage
            }
        }
```
