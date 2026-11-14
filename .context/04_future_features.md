# 04_future_features.md — Future Features, Unwired Subsystems & Legacy Migration

## 1. Executive Summary

While `qh-bot` provides an end-to-end 9-stage Microsoft account recovery engine, several subsystems remain stubbed, unwired, or blocked by upstream Microsoft interface changes. Additionally, architectural comparisons with the legacy JavaScript implementation (`/legacy_full_bot` / `recodesecure.js`) reveal significant design evolutions and identify remaining opportunities for capability expansion.

---

## 2. Unwired & Stubbed Features in Modern Codebase

### 2.1 Minecraft Ownership Verification Subsystem Integration
- **Current State:**
  A comprehensive Minecraft ownership verification subsystem is fully implemented in `tech.qhuyy.minecraft.ownership`:
  - `MinecraftOwnershipService.kt`: Executes the 4-step Xbox Live / Mojang entitlement verification pipeline:
    1. Authenticates Microsoft OAuth access token with Xbox Live (`POST https://user.auth.xboxlive.com/user/authenticate`).
    2. Exchanges Xbox token for XSTS token (`POST https://xsts.auth.xboxlive.com/xsts/authorize`, relying party `rp://api.minecraftservices.com/`). Maps numeric error codes (e.g. child account `2148916238`, banned `2148916235`) via `XstsErrorMapper`.
    3. Authenticates with Mojang Services using XSTS token (`POST https://api.minecraftservices.com/authentication/login_with_xbox`).
    4. Queries game licenses (`GET https://api.minecraftservices.com/entitlements/license`) and player profile (`GET https://api.minecraftservices.com/minecraft/profile`).
  - Unit Test Suite: 10 dedicated test cases in `MinecraftOwnershipServiceTest.kt` verifying all entitlement branches and error conditions.
  - Standalone Runner: `MinecraftOwnershipDemo.kt` runnable via `./gradlew runDemo`.
- **The Gap:**
  1. `Main.kt` loads only `kordModule` and `databaseModule` during startup, completely omitting `minecraftOwnershipModule`.
  2. `RecoveryWorkflow.kt` (line 81) and `RecoveryInteractionEvent.kt` (line 86) currently hardcode `ownsMinecraft = false` when committing recovered accounts to SQLite.
- **Integration Roadmap:**
  To complete the integration:
  1. Register `minecraftOwnershipModule` in `Main.kt`.
  2. Introduce a post-recovery token exchange step (e.g. MSAL Device Code Flow or OAuth authorize code grant) using the newly reset credentials.
  3. Pass the resulting Microsoft access token to `MinecraftOwnershipService.checkOwnership()`.
  4. Persist the returned `owns_minecraft` boolean flag and player IGN/UUID into SQLite via `accountRepository.updateMinecraftStatus()`.

---

### 2.2 2FA TOTP App Reconfiguration (Blocked by DOM Removal)
- **Current State:**
  Stage 9 cleanly disables legacy two-factor authentication proofs (`POST /API/Proofs/DisableTfa`), deletes device sessions, and removes passkeys.
- **The Gap:**
  Re-enabling two-factor authentication with a newly generated TOTP authenticator key (`POST https://account.live.com/API/AddVerifyTotp`, documented in `core.txt` Section 6) is absent from the modern codebase.
- **The Microsoft Blocker:**
  In `core.txt` Section 6, forensic notes explain that Microsoft recently redesigned the Authenticator setup UI:
  - The historical HTML selector `<span class="dirltr bold">` previously used to scrape the base32 TOTP `secretKey` was completely removed from the page DOM.
  - The secret key is now rendered within dynamic client-side WebAssembly / React components or obscured behind private JavaScript state.
  - Automated headless scraping of the secret key is blocked without deploying full browser automation (e.g. Playwright / Puppeteer) or discovering undocumented private REST APIs.

---

### 2.3 Transition to Native Outlook Alias Mode
- **Current State:**
  `AliasClient.kt` defaults to registering custom domain aliases (`@qhuyy.tech`) and polling an external Cloudflare Worker (`https://qh-bot.qhuyy.tech/get-otc`) using HMAC-SHA256 signatures to retrieve email verification codes. If `SHARED_SECRET` is unset, it prompts the operator via a Discord modal.
- **The Opportunity:**
  In `core.txt` Section 5, empirical testing proved that adding a native `@outlook.com` alias (`SingleDomain=outlook.com`, `AddAssocIdOptions=LIVE`) requires **ZERO email verification**:
  - Microsoft automatically binds the `@outlook.com` alias without sending an OTC code.
  - By transitioning the default alias generation from custom domains to native Outlook aliases, the bot can completely eliminate its dependency on external Cloudflare Workers, HMAC secrets, and manual Discord OTC prompts.

---

### 2.4 Discord Slash Command Palette Expansion
- **Current State:**
  Only `/ping` (`PingCommand.kt`) is registered as a global slash command. Account recovery is triggered solely via button interaction (`start_recovery_btn`) posted on bot startup.
- **Planned Commands:**
  - `/lookup <email>`: Queries SQLite database and displays current recovery status, primary alias, and Minecraft ownership details.
  - `/retry <email>`: Allows re-running recovery on failed accounts without re-entering all initial parameters.
  - `/stats`: Displays aggregate statistics (total recovered, success rate, pending operations).
  - `/export`: Exports recovered credentials for authorized operators.

---

## 3. Comparison with Legacy Codebase (`/legacy_full_bot` / `recodesecure.js`)

`prompt.txt` and `core.txt` reference an earlier Node.js codebase (`/legacy_full_bot`, with central file `recodesecure.js`). A comparative evaluation highlights the architectural advances implemented in `qh-bot`:

| Dimension | Legacy Node.js (`recodesecure.js`) | Modern Kotlin (`qh-bot`) | Engineering Rationale |
|---|---|---|---|
| **Architecture** | Monolithic God Script exceeding 1,500 lines mixing HTTP scraping, Discord UI, and database logic. | Clean Architecture: Koin DI, isolated 9-stage handlers (`Stage1`..`Stage9`), `RecoveryWorkflow` coordinator, and dedicated repositories. | Eliminates coupling; allows individual stages to be updated or mocked without breaking adjacent steps. |
| **Concurrency & Pipeline Safety** | Executed operations concurrently via `Promise.all` (simultaneous alias change, passkey removal, avatar update, 2FA toggle). | Strict linear sequential pipeline with bounded delays (`stageDelayMs`) and transactional state transitions. | Concurrent operations on Microsoft accounts trigger WAF race conditions, corrupting account credentials mid-flight. |
| **Session Scoping & Cookies** | Naive string-concatenated `Cookie` headers or monolithic unmanaged cookie jars. | Ktor `AcceptAllCookiesStorage` with explicit cross-domain replication (`login.live.com` $\leftrightarrow$ `account.live.com`). | Eliminates session loss and complies with RFC 6265bis `__Host-` cookie partitioning rules. |
| **Discord Rate Limits** | Dispatched embeds and messages on every single step and debug trace, triggering aggressive Discord HTTP 429 rate limits. | Atomic single-failure embed deduplication (`AtomicBoolean`) and intermediate success suppression; debug logs buffered in memory. | Completely eliminates Discord HTTP 429 rate limits and gateway stalls while providing richer diagnostic data on failure. |
| **Minecraft Check** | Scraped OAuth endpoint `oauth20_authorize.srf?client_id=00000000402B5328` (now blocked by Microsoft consent interstitials and captchas). | Modern REST client (`MinecraftOwnershipService`): Xbox Live -> XSTS -> Minecraft Services Bearer -> Entitlements -> Profile API. | Complies with Microsoft's modern identity architecture; resilient against web scraping blocks. |
| **Database Persistence** | Basic SQLite without status tracking or failure diagnostics. | Migrated SQLite schema with `status` (PENDING, SUCCESS, FAILED), `fail_reason`, timestamps, and idempotency checks. | Prevents re-running already secured accounts, avoiding Microsoft risk bans and IP penalties. |

---

## 4. Recommended Roadmap & Next Actions

1. **Step 1 — Wire `MinecraftOwnershipService` into Bot:**
   - Bind `minecraftOwnershipModule` in `Main.kt`.
   - Implement post-recovery token retrieval and link it into `RecoveryWorkflow`.
2. **Step 2 — Default to Native Outlook Aliases:**
   - Configure `RecoveryService` to use native `@outlook.com` alias rotation as the primary path, keeping the Cloudflare Worker as an optional secondary path for custom domains.
3. **Step 3 — Implement Administrative Slash Commands:**
   - Add `/lookup` and `/stats` commands to `CommandManager`.
4. **Step 4 — Research Dynamic TOTP Extraction:**
   - Investigate headless browser automation or private Microsoft Graph/Account APIs to restore automated TOTP 2FA re-enabling.
