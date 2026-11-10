# Recovery Flow Inconsistency Report

> **Auditor:** [K]vk — Senior Kotlin Security & API Integration Auditor
> **Date:** 2026-11-10
> **Scope:** `microsoft.recovery` package (`RecoveryService.kt`, `AliasClient.kt`, `RecoveryParsers.kt`, `MicrosoftHttpClientFactory.kt`, model classes)
> **Reference:** `core.txt` (verified 2026-11-08 via live curl)

---

## 1. Executive Summary

The codebase is architecturally sound for Stages 1–7. The primary failures cluster around **Stage 8 (Alias Rotation)**, with the root cause being a combination of:

1. **`AssociatedIdLive` sends the full `user@domain` in the `AliasClient` path but only the prefix in `core.txt`** — `core.txt` specifies `AssociatedIdLive=<alias_prefix>` (just the prefix, e.g. `lencak480`), not the full email. The code sends `lencak480@qhuyy.tech`. This is the **#1 most likely cause** of the OAuth redirect, because `@qhuyy.tech` is a custom domain and Microsoft's `AddAssocId` form expects either an `@outlook.com` prefix OR requires `SingleDomain` to be set to the custom domain.
2. **`SingleDomain` is hardcoded to `""` (empty string)** instead of `outlook.com` (as specified by `core.txt`). When using a custom domain like `qhuyy.tech`, this parameter likely needs to match the domain or be omitted entirely.
3. **`uaid` form parameter**: Now correctly extracts from cookie (after recent fix), but the `MakePrimary` fallback path in `RecoveryService.kt` still sends the random `uaid` from `executeLifecycle` (line 1344: `uaid = uaid`).
4. **Missing `X-Requested-With: XMLHttpRequest` header** on Stage 4 `GET /proofs/manage/additional` — `core.txt` specifies it; the code omits it.
5. **Stage 3 isolated client lacks `HttpCookies` plugin** — the `polishResponse` client doesn't persist cookies from redirects, so any intermediate `Set-Cookie` headers are lost.

No critical issues were found in Stages 1, 2, 2b, 5, 6, or 7. Stage 9 is structurally correct.

---

## 2. Session & Cookie Lifecycle Analysis

### 2.1 Cookie Storage Architecture

The system uses a single `AcceptAllCookiesStorage` instance (`cookieStorage`) created in `runLifecycle()` (line 110). This storage is shared across the main `HttpClient` and manually passed to Stage 3 and Stage 8 helper functions.

**Cookie flow:**

```
Stage 1 (GET login.srf)          → uaid, MSPOK, MSPRequ stored by Ktor CookieJar
Stage 1 (POST GetCredentialType) → OParams cookie may arrive
Stage 2b (POST ppsecure/post)    → __Host-MSAAUTH stored (manually + by Ktor)
Stage 3 (GET login.srf?wa=...)   → Uses ISOLATED client (NO CookieJar) with manual Cookie header
Stage 3 (POST /proofs/Add)       → AMRPSSecAuth + amsc captured via manual Set-Cookie parsing
Stage 4+ (main client)           → Uses shared cookieStorage with all accumulated cookies
Stage 8 (POST /AddAssocId)       → Uses ISOLATED noRedirectClient with manual Cookie header
```

### 2.2 Stage 3 Cookie Loss Vector

**Problem:** The Stage 3 GET request to `login.srf?wa=wsignin1.0&...` uses an `isolatedClient` (line 492–502) that has **no `HttpCookies` plugin installed**. This means:

- Any `Set-Cookie` headers returned by Microsoft during the GET request or its redirects are **silently dropped**.
- If Microsoft rotates `uaid` or issues new session cookies during this step, they are lost.
- The `DoSubmit()` intermediate POST form (`submitStage3IntermediateForm`) also uses a cookie-less client with only a manual `Cookie` header — any `Set-Cookie` responses from the intermediate hop are also lost.

The `submitStage3AddProofForm` client (line 670–684) DOES have `HttpCookies` installed with the shared `cookieStorage`, which is correct for capturing `AMRPSSecAuth` and `amsc`. However, the initial GET that precedes it does not.

### 2.3 Stage 8 Cookie Isolation (Correct)

The `buildStage8CookieHeader` / `buildIsolatedAccountCookieHeader` functions correctly merge cookies from both `login.live.com` and `account.live.com` storage, filter to only `__Host-MSAAUTH`, `AMRPSSecAuth`, and `amsc`, and attach them as a single manual `Cookie` header. This prevents domain-filtering issues with `__Host-` prefixed cookies.

`persistAccountSetCookies` correctly writes `Set-Cookie` responses back to the shared storage.

### 2.4 `__Host-MSAAUTH` Domain Concern

In Stage 2b (line 451–454), `__Host-MSAAUTH` is stored with `domain = "login.live.com"`. The `__Host-` prefix per RFC 6265bis means the cookie should have **no `Domain` attribute** (host-only). Ktor's `AcceptAllCookiesStorage` doesn't enforce this, so the cookie is only returned for queries to `login.live.com`, NOT `account.live.com`. This is why manual cookie headers are necessary for `account.live.com` requests — and the code handles this correctly in Stages 4+ and 8.

---

## 3. The UAID Problem

### 3.1 UAID Lifecycle

```
executeLifecycle() line 157:  var uaid = RecoveryParsers.generateUaid()  ← RANDOM
                   line 171:  uaid = cookieStorage["login.live.com"]["uaid"]  ← From Stage 1/2 cookies (if present)
                   line 179:  uaid = cookieStorage["account.live.com"]["uaid"] ?? cookieStorage["login.live.com"]["uaid"]  ← After Stage 3

This `uaid` variable is passed to:
  → Stage 3 (URL parameter + Cookie header)  ✓ correct
  → Stage 7 (SetUserNotificationState JSON body)  ✓ correct
  → Stage 8 (via `sessionUaid` parameter to AliasClient)  ⚠ see below
  → Stage 9 (SecurityCleanupRequest JSON body)  ✓ correct
```

### 3.2 Stage 8 UAID — AliasClient Path (Current State)

After the recent fix, `AliasClient.rotateAlias()` correctly:
1. Calls `extractLoginUaidCookie()` to read `uaid` from `login.live.com` cookie storage.
2. If found, includes `"uaid" to refreshedCookieUaid` in the `AddAssocId` form body.
3. If NOT found, **omits** `uaid` entirely from the form body.

This is correct behavior per the debugging conclusion.

### 3.3 Stage 8 UAID — RecoveryService Fallback Path (Line 1183–1382)

The `else` branch (when `aliasClient == null`) now also correctly:
1. Reads `actualCookieUaid` from `cookieStorage.get(Url("https://login.live.com"))`.
2. Conditionally includes `uaid` only when `actualCookieUaid != null`.

**However**, the `MakePrimary` request in this fallback branch (line 1344) still uses `uaid = uaid` — the `uaid` variable from `executeLifecycle` scope, which may be the initially-generated random value if no `uaid` cookie was set by Microsoft. This is acceptable because `MakePrimary` is a JSON API that always requires `uaid` (non-nullable in `MakePrimaryRequest`), and by this point the `uaid` variable should have been updated from cookies.

### 3.4 core.txt Says UAID Should Be Dynamic

> **Section 3.4:** "Tuyệt đối không hardcode `uaid`. Phải generate ngẫu nhiên 32 ký tự hex cho mỗi session."

The code generates a random UAID per session and updates it from cookies. This is correct. The vulnerability assessment in `core.txt` also criticizes the **original Node.js script** for using static UAIDs — the Kotlin code does not have this problem.

---

## 4. Stage-by-Stage Discrepancy Table

| Stage | API Endpoint | `core.txt` Expected Behavior | Current Code Status | Severity |
|-------|-------------|-------------------------------|---------------------|----------|
| **1** | `GET login.srf` | Standard GET, extract PPFT from `ServerData.sFTAg` | ✅ Correct — Uses `RecoveryParsers.extractPpft` which parses ServerData JSON → sFTAg → Jsoup/regex extraction | None |
| **1** | `POST GetCredentialType.srf` | Payload includes `username`, `flowToken`, `checkPhones`, `isUcuxLoginForm` | ✅ Correct — `GetCredentialTypeRequest` matches. Missing `federationFlags`, `isRemoteNGCSupported`, `isFidoSupported`, `otclogindisallowed` from `core.json` but these are optional/default values | Low |
| **2** | `POST GetOneTimeCode.srf` | Form: `login`, `flowtoken`, `purpose=eOTT_OtcLogin`, `channel`, `AltEmailE` | ✅ Correct | None |
| **2** | State 201/206 handling | Continue if `FlowToken` present, don't throw | ✅ Correct — Line 397 logs warning but continues | None |
| **2b** | `POST ppsecure/post.srf` | Form: `login`, `loginfmt`, `type=27`, `SentProofIDE`, `otc`, `PPFT`, `LoginOptions=3` | ✅ Correct | None |
| **3** | `GET login.srf?wa=wsignin1.0&...` | Cookie: `__Host-MSAAUTH=<session>`. Extract token `t`. | ⚠️ Isolated client has **no HttpCookies plugin** — intermediate Set-Cookie headers from redirects are lost | Medium |
| **3** | `POST /proofs/Add` | Form: `t=<token_t>`. Response: 302 with `AMRPSSecAuth` + `amsc` cookies | ✅ Correct — `submitStage3AddProofForm` uses `followRedirects = false` and captures cookies | None |
| **4** | `GET /proofs/manage/additional` | Headers: `X-Requested-With: XMLHttpRequest`, `Cookie: AMRPSSecAuth=...; amsc=...; __Host-MSAAUTH=...` | ⚠️ **Missing `X-Requested-With: XMLHttpRequest` header.** `core.txt` "Security Proofs & NetId Extraction" specifies it. The code sends the request through the main client which adds default headers but not `X-Requested-With`. | Medium |
| **5** | `POST GenerateRecoveryCode` | Headers: `canary`, `x-ms-apiVersion: 2`, `x-ms-apiTransport: xhr`. Payload: `{encryptedNetId}` | ✅ Correct — Both version headers present (lines 845–846) | None |
| **6** | `GET ResetPassword.aspx` | Extract `sRecoveryToken` and `apiCanary` from `ServerData` | ✅ Correct — `RecoveryParsers.extractResetPasswordData` handles Unicode decode | None |
| **6** | `POST VerifyRecoveryCode` | Payload: `publicKey`, `recoveryCode`, `code`, `scid: 100103`, `token` (= sRecoveryToken), `uiflvr: 1001` | ✅ Correct — `VerifyRecoveryCodeRequest` matches exactly. `scid` is `Int` (100103), matches `core.txt` which shows both `100103` (int) and `"100103"` (string) | None |
| **6** | `POST RecoverUser` | Payload: `contactEmail`, `contactEpid: ""`, `password`, `passwordExpiryEnabled: 0`, `publicKey`, `token` (= verification grant) | ✅ Correct — Uses `canaryAfterVerify` (from VerifyRecoveryCode response). `contactEmail` correctly falls back to `""` when same as original | None |
| **7** | `POST SetUserNotificationState` | Payload: `proofDetails[{name, notificationEnabled: false, type}]`, `uiflvr`, `uaid`, `scid: 100109`, `hpgid: 201030` | ✅ Correct — `SetUserNotificationStateRequest` matches. Iterates all proofs sequentially with fail-closed | None |
| **8** | `POST AddAssocId` | `core.txt`: `AssociatedIdLive=<alias_prefix>`, `SingleDomain=outlook.com` | ❌ **Code sends full email** (`lencak480@qhuyy.tech`) as `AssociatedIdLive`. `core.txt` shows `AssociatedIdLive=<new_prefix>` (just the prefix). `SingleDomain` is `""` instead of `"outlook.com"`. | **Critical** |
| **8** | `POST AddAssocId` | `core.txt`: `canary=<canary>` in form body. No `uaid` parameter mentioned | ⚠️ `uaid` is conditionally included — not in `core.txt` spec. May or may not cause issues. The `canary` header is sent in addition to the form body `canary` — `core.txt` only specifies the form body | Low |
| **8** | `POST MakePrimary` | `core.txt`: `{aliasName, emailChecked: true, removeOldPrimary: false}` — no `uiflvr/uaid/scid/hpgid` shown in basic spec, but `core.json` shows them | ✅ Correct — `MakePrimaryRequest` includes all fields | None |
| **8** | `POST /names/manage` | Form: `canary`, `action=RemoveAlias`, `aliasName=<old>`, `displayName=<old>` | ✅ Correct | None |
| **9** | All cleanup POSTs | `canary` header, `X-Requested-With: XMLHttpRequest`, JSON body with `uiflvr/uaid/scid/hpgid` | ✅ Correct — `X-Requested-With` is present (line 1437, 1449 etc.) | None |

---

## 5. Specific Code Fixes Required

### Fix #1 — CRITICAL: `AssociatedIdLive` and `SingleDomain` Mismatch

**Location:** `AliasClient.kt` lines 125–135 and `RecoveryService.kt` lines 1249–1255

**Problem:**
`core.txt` line 136:
```
Payload (Form): canary=<canary>&PostOption=NONE&SingleDomain=outlook.com&AddAssocIdOptions=LIVE&AssociatedIdLive=<new_prefix>
```

`core.json` line 566:
```
"payload": "canary=<canary2>&PostOption=NONE&SingleDomain=outlook.com&UpSell=&AddAssocIdOptions=LIVE&AssociatedIdLive=<alias_prefix>"
```

Both sources show:
- `AssociatedIdLive` = **just the prefix** (e.g., `lencak480`), NOT the full email
- `SingleDomain` = `outlook.com`

**Current code sends:**
- `AssociatedIdLive` = `lencak480@qhuyy.tech` (full email with custom domain)
- `SingleDomain` = `""` (empty string)

**Why this matters:**
Microsoft's `AddAssocId` endpoint interprets `AssociatedIdLive` as a prefix and combines it with `SingleDomain` to form the alias email. When receiving `lencak480@qhuyy.tech` as a prefix with `SingleDomain=""`, Microsoft may:
1. Not recognize the custom domain and reject the request
2. Redirect to OAuth because the payload is malformed

**However — important caveat:** The `core.txt` spec was verified with `@outlook.com` aliases. For custom domain `@qhuyy.tech` aliases, the behavior may differ. The form MAY need `AssociatedIdLive=lencak480@qhuyy.tech` with `SingleDomain=""` or `SingleDomain=qhuyy.tech`. This needs empirical testing.

**Recommended action:**
- Test with `AssociatedIdLive=lencak480` + `SingleDomain=outlook.com` first (matches `core.txt` exactly)
- If custom domain is required, test with `AssociatedIdLive=lencak480` + `SingleDomain=qhuyy.tech`
- Log the exact form parameters and Microsoft's response in both cases

---

### Fix #2 — MEDIUM: Missing `X-Requested-With: XMLHttpRequest` on Stage 4

**Location:** `RecoveryService.kt` line 781

**Problem:**
`core.txt` / `core.json` "Security Proofs & NetId Extraction" entry specifies:
```json
"headers": {
    "X-Requested-With": "XMLHttpRequest",
    "Cookie": "AMRPSSecAuth=<amrp>; amsc=<amsc>; __Host-MSAAUTH=<host>"
}
```

The current code:
```kotlin
val manageProofsResponse = client.get("https://account.live.com/proofs/manage/additional")
```
This uses the default client with no `X-Requested-With` header. The default request configuration in `MicrosoftHttpClientFactory` only sets `User-Agent`, `Accept-Language`, and `Accept`.

**Impact:** Microsoft may return a different HTML structure (full page vs. XHR fragment) or redirect to an interstitial page when `X-Requested-With` is missing. The Stage 4 extraction currently works (tests pass), but this divergence from the spec could cause intermittent failures on certain Microsoft backend versions.

**Fix:**
```kotlin
val manageProofsResponse = client.get("https://account.live.com/proofs/manage/additional") {
    header("X-Requested-With", "XMLHttpRequest")
}
```

---

### Fix #3 — MEDIUM: Stage 3 Isolated Client Drops Intermediate Cookies

**Location:** `RecoveryService.kt` lines 492–522

**Problem:**
The `isolatedClient` for Stage 3's initial GET request has `followRedirects = true` and `HttpRedirect { checkHttpMethod = false }` but **no `HttpCookies` plugin**. This means:

1. If Microsoft issues a redirect chain (e.g., `login.srf` → intermediate → final page), any `Set-Cookie` headers in intermediate responses are silently discarded.
2. The `uaid` cookie that Microsoft may rotate during this step is lost.
3. Any session cookies set during the redirect chain are not available to subsequent requests.

The manual `Cookie` header on the outgoing request works fine for SENDING cookies, but RECEIVING new cookies requires the `HttpCookies` plugin.

**Fix:**
```kotlin
val isolatedClient = HttpClient(clientEngine ?: OkHttp.create()) {
    followRedirects = true
    install(HttpRedirect) { checkHttpMethod = false }
    install(HttpCookies) {
        storage = cookieStorage
    }
}
```

Then remove the manual `header(HttpHeaders.Cookie, cleanCookieHeader)` and let Ktor handle cookie sending automatically, OR keep the manual header but add the `HttpCookies` plugin to capture response cookies.

**Caveat:** Adding `HttpCookies` may cause duplicate `Cookie` headers if you also set a manual one. Choose one approach:
- **Option A:** Install `HttpCookies` and remove the manual `Cookie` header. Ensure `__Host-MSAAUTH` is accessible from `cookieStorage` for `login.live.com` queries (it is, per line 451–454).
- **Option B:** Keep the manual `Cookie` header, don't install `HttpCookies`, but manually parse `Set-Cookie` from the response (like `captureStage3AccountCookies` does). This is more work but gives full control.

---

## 6. Additional Observations (Low Severity)

### 6.1 `GetCredentialTypeRequest` Missing Fields
`core.json` specifies `federationFlags: 3`, `isRemoteNGCSupported: true`, `isFidoSupported: true`, `otclogindisallowed: false`. The current `GetCredentialTypeRequest` omits these. These are likely optional/defaulted server-side and the code works without them, but including them would more closely match the browser fingerprint.

### 6.2 `VerifyRecoveryCode` scid Type
`core.txt` line 121 shows `"scid": 100103` (integer). `core.json` line 472 shows `"scid": 100103` (integer). The `VerifyRecoveryCodeRequest` model uses `val scid: Int = 100103`. This is correct — `kotlinx.serialization` will serialize it as a JSON integer.

### 6.3 Canary Rotation Chain is Correct
The code properly chains canary updates:
- Stage 4 → `proofsData.apiCanary`
- Stage 5 → `genCodeData.apiCanary` (if present, else previous)
- Stage 6 → `resetData.apiCanary` → `verifyData.apiCanary` → `recoverUserData.apiCanary`
- Stage 7 → Each `SetUserNotificationState` response updates canary
- Stage 8 → Refreshed from `GET /proofs/manage/additional`

This matches the `core.txt` specification that each API response may contain a rotated `apiCanary`.

### 6.4 `maxSendCount = 1000`
`MicrosoftHttpClientFactory` sets `maxSendCount = 1000` (line 54). This is very high and means the client will follow up to 1000 redirects. For most stages this is fine (the client follows redirects by design), but for Stage 8 where redirect-following is explicitly disabled via a separate client, this doesn't matter.

### 6.5 `RemoveAlias` Response Validation
The fallback branch `RemoveAlias` (RecoveryService line 1376) only checks `isSuccess()` but does not verify `Note_AssociatedIdRemoved` in the response body. The `AliasClient` version (line 602) does check for this confirmation string. The fallback branch should match.

---

## 7. Priority Matrix

| # | Issue | Severity | Confidence | Effort |
|---|-------|----------|------------|--------|
| 1 | `AssociatedIdLive` sends full email vs prefix | **Critical** | Medium (needs empirical test) | Low |
| 2 | `SingleDomain` is `""` vs `"outlook.com"` | **Critical** | Medium (needs empirical test) | Low |
| 3 | Missing `X-Requested-With` on Stage 4 | Medium | High | Trivial |
| 4 | Stage 3 isolated client drops intermediate cookies | Medium | Medium | Low |
| 5 | `GetCredentialTypeRequest` missing optional fields | Low | Low | Trivial |
| 6 | Fallback `RemoveAlias` doesn't verify confirmation | Low | High | Trivial |

> **Recommendation:** Items 1 and 2 require **empirical testing** with live Microsoft endpoints. The `core.txt` curl session used `@outlook.com` aliases, so the `AddAssocId` form parameters may behave differently for custom domains. Run a controlled test with debug logging to capture the exact Microsoft response.
