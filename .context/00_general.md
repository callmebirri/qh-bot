# 00_general.md — Qh-Bot System Overview & Architecture

## 1. Project Overview

`qh-bot` is an automated Microsoft Account Recovery, Security Maintenance, and Alias Rotation Discord bot and backend engine written in Kotlin. It implements an empirically verified 9-stage HTTP protocol workflow against Microsoft authentication and identity management endpoints (`login.live.com` and `account.live.com`).

The bot performs the following primary functions:
1. **Interactive Discord Workflow:** Guides server operators through account recovery via ephemeral modals, buttons, and status embeds built on the Kord framework.
2. **Automated Account Recovery:** Dispatches One-Time Codes (OTP) to registered account proofs (email/SMS), establishes an authenticated session, elevates the session to Strong Authentication (AMRP `SA_20MIN`), extracts emergency recovery tokens, resets passwords, and generates new emergency recovery codes.
3. **Notification Suppression (Fail-Closed):** Disables security notification alerts across all registered email and SMS proofs to prevent alerting the original owner during security rotation.
4. **Primary Alias Rotation:** Adds a new alias (either a native `@outlook.com` alias or a custom domain alias verified via an HMAC-authenticated Cloudflare Worker or Discord modal), promotes the new alias to primary, and removes the compromised original alias.
5. **Security Cleanup & Session Revocation:** Revokes all active device sessions, refresh tokens, app passwords, and WebAuthn/FIDO2 passkeys, and disables legacy two-factor authentication.
6. **Local Persistence & Idempotency:** Persists recovered account credentials and status in a local SQLite database with single-connection HikariCP pooling to prevent re-running already secured accounts.
7. **Minecraft Ownership Verification Subsystem:** Interfaces with Xbox Live authentication and Mojang/Minecraft Entitlements API to verify game license ownership and player profile details.

---

## 2. Tech Stack & Verified Versions

The bot is developed with modern Kotlin 2.4 on the Java Virtual Machine (JVM 21) with an asynchronous coroutine-driven architecture:

| Category | Component / Dependency | Verified Version | Maven Coordinates / Identifier | Role & Responsibility |
|---|---|---|---|---|
| **Language Runtime** | Kotlin JVM | `2.4.21` | `org.jetbrains.kotlin.jvm` | Core programming language runtime (JVM target 21) |
| **Toolchain Resolver** | Foojay Toolchain Convention | `1.0.0` | `org.gradle.toolchains.foojay-resolver-convention` | Automated JDK 21 toolchain provisioning |
| **Build Tool** | Gradle Wrapper | `9.8.0` | N/A | Build lifecycle and task automation |
| **Fat JAR Plugin** | GradleUp Shadow | `9.6.1` | `com.gradleup.shadow` | Bundles runnable standalone JAR (`tasks.shadowJar`) |
| **Discord API** | Kord Core | `0.18.1` | `dev.kord:kord-core` | Asynchronous Discord Gateway, interaction, and REST client |
| **HTTP Engine** | Ktor Client OkHttp | `3.6.1` | `io.ktor:ktor-client-okhttp` | HTTP client engine for outbound Microsoft and Mojang requests |
| **HTTP Plugins** | Ktor Content Negotiation | `3.6.1` | `io.ktor:ktor-client-content-negotiation` | JSON serialization/deserialization integration |
| **HTTP Mocking** | Ktor Client Mock | `3.6.1` | `io.ktor:ktor-client-mock` | Deterministic HTTP engine mocking for unit testing |
| **Dependency Injection** | Koin Core | `4.2.2` | `io.insert-koin:koin-core` | Pragmatic dependency injection container |
| **Serialization** | Kotlinx Serialization JSON | `1.11.0` | `org.jetbrains.kotlinx:kotlinx-serialization-json` | High-performance JSON parser with Unicode decoding |
| **Concurrency** | Kotlinx Coroutines Core | `1.11.0` | `org.jetbrains.kotlinx:kotlinx-coroutines-core` | Asynchronous scopes, deferred values, and timeouts |
| **Database Driver** | SQLite JDBC | `3.54.1.0` | `org.xerial:sqlite-jdbc` | Embedded relational persistence driver |
| **Connection Pooling** | HikariCP | `7.1.0` | `com.zaxxer:HikariCP` | High-performance JDBC connection pool (max pool size = 1) |
| **HTML Parser** | Jsoup | `1.24.1` | `org.jsoup:jsoup` | DOM inspection for scraping forms, PPFT, and token `t` |
| **Logging Framework** | Logback Classic | `1.6.6` | `ch.qos.logback:logback-classic` | SLF4J implementation for console and rolling file logs |
| **Test Framework** | Kotlin Test JUnit5 | `2.4.21` | `org.jetbrains.kotlin:kotlin-test` | Unit test assertions and runner |

---

## 3. High-Level Architecture Flow

```
                           APPLICATION ENTRY POINT
                                  Main.kt
                                     │
                 ┌───────────────────┴───────────────────┐
                 ▼                                       ▼
           kordModule                              databaseModule
     (Kord, Config, Logger,                     (HikariCP, SQLite,
      Service, Commands)                        AccountRepository)
                 │                                       │
                 ▼                                       │
       EventManager.registerAll()                        │
       CommandManager.registerAll()                      │
                 │                                       │
                 ▼                                       │
       Discord Gateway Connect                           │
                 │                                       │
      [User Interaction / Modal]                         │
                 │                                       │
                 ▼                                       ▼
     RecoveryInteractionEvent ────────────► SqliteAccountRepository
                 │                           (Idempotency Check:
                 │                            Abort if SUCCESS)
                 ▼
          RecoveryService
    (Creates HttpClient, CookieJar,
        generates UAID & Password)
                 │
                 ▼
          RecoveryWorkflow
                 │
  ┌──────────────┴──────────────────────────────────────────────────────┐
  ▼                                                                     ▼
Stage 1: Discovery (login.srf -> GetCredentialType.srf)               Success
Stage 2: OTP Dispatch & Submit (GetOneTimeCode -> ppsecure/post.srf)    │
Stage 3: Session Polish (login.srf?wp=SA_20MIN -> proofs/Add)           ▼
Stage 4: Proofs Enumeration (proofs/manage/additional)               Save to DB
Stage 5: Recovery Code Gen (API/Proofs/GenerateRecoveryCode)         (SUCCESS)
Stage 6: Password Reset (ResetPassword.aspx -> RecoverUser)             │
Stage 7: Notification Suppression (API/Proofs/SetUserNotificationState) ▼
Stage 8: Alias Rotation (AddAssocId -> MakePrimary -> RemoveAlias)   Post Final
Stage 9: Security Cleanup (DisableTfa -> DeleteDevices -> Passkeys)   Result Embed
                 │
                 ▼ (On Any Failure)
       Failure Stage Abort
                 │
                 ▼
       Single Failure Embed
    (Emitted once via AtomicBoolean)
```

### Detailed Component Roles:
1. **`Main.kt`**: Application entry point. Loads the Discord Bot Token (`DBT`), instantiates the Kord client, builds the Koin dependency injection graph, registers event listeners and slash commands, and opens the Discord Gateway connection.
2. **`config/BotPropertiesManager.kt`**: Loads external bot configuration properties (`config.properties`), including `guild_id`, `log_channel_id`, `noti_channel_id`, and `role_id`.
3. **`event/events/RecoveryInteractionEvent.kt`**: Coordinates user interaction:
   - Receives button click (`start_recovery_btn`) and presents Step 1 Modal (ign, email).
   - Defers ephemeral response and launches asynchronous recovery coroutine.
   - Manages interactive OTP modal prompts (`recovery_step2_modal`) and manual alias OTC prompts (`recovery_alias_otc_modal`) using `CompletableDeferred` bridges.
   - Enforces failure-only Discord logging: suppresses intermediate stage notifications, captures debug HTML/HTTP traces, and emits exactly one detailed failure embed via an `AtomicBoolean` deduplication guard.
4. **`microsoft.recovery.RecoveryService`**: Facade for the recovery pipeline. Validates input parameters, derives new alias candidates, initializes an isolated Ktor `HttpClient` with `AcceptAllCookiesStorage`, constructs the mutable `RecoveryContext`, and invokes `RecoveryWorkflow`.
5. **`microsoft.recovery.RecoveryWorkflow`**: Coordinates the sequential execution of Stages 1 through 9. Enforces inter-stage delays (`stageDelayMs`), handles early termination flags (`stopAfterStage7`), updates recovery status, and saves results to `AccountRepository`.
6. **`microsoft.recovery.stages.*`**: Nine dedicated stage implementations conforming to `RecoveryStageHandler`:
   - `Stage1Discovery`: Discovers eligible proofs and extracts flow tokens.
   - `Stage2Otp`: Requests OTP code, receives user submission, and captures `__Host-MSAAUTH`.
   - `Stage3Polish`: Resolves `DoSubmit()` interstitial forms and elevates session to AMRP `SA_20MIN`.
   - `Stage4Proofs`: Scrapes registered proofs, `encryptedNetId`, and initial canary.
   - `Stage5RecoveryCode`: Generates 25-character emergency recovery code.
   - `Stage6PasswordReset`: Scrapes reset tokens, verifies recovery code, and overrides account password.
   - `Stage7Suppression`: Sequentially suppresses email and SMS alert notifications (fail-closed).
   - `Stage8Alias`: Adds alias, verifies OTC (worker or manual), promotes to primary, and removes old alias.
   - `Stage9Cleanup`: Disables 2FA, revokes sessions/devices/app passwords, and deletes passkeys.
7. **`database/repository/SqliteAccountRepository.kt`**: Thread-safe JDBC persistence layer backed by HikariCP single-connection pool (`maximumPoolSize = 1`). Executes queries on `Dispatchers.IO` and performs in-place schema migrations.

---

## 4. Concise Project File Tree

```
c:\Users\birrisme\qh-bot\
├── build.gradle.kts                            # Gradle build script (Kotlin 2.4.21, JVM 21, Shadow, Kord, Ktor)
├── settings.gradle.kts                         # Gradle settings and Foojay toolchain plugin
├── gradle.properties                           # Compiler flags and code style configuration
├── config.properties                           # Operational Discord channel, role, and guild IDs
├── core.txt                                    # Empirically verified Microsoft HTTP protocol specification
├── report.md                                   # Forensic engineering audit report of recovery flow bugs
├── prompt.txt                                  # Initial context and architectural migration instructions
├── gradle/
│   ├── wrapper/
│   │   ├── gradle-wrapper.jar                  # Gradle wrapper binary
│   │   └── gradle-wrapper.properties           # Wrapper version declaration (Gradle 9.8.0)
│   └── libs.versions.toml                      # Version catalog for dependencies and plugins
├── .context/                                   # Repository knowledge base and external brain
│   ├── core.txt                                # Verbatim copy of core.txt specification
│   ├── 00_general.md                           # System overview, tech stack, architecture, file tree
│   ├── 01_scraping_chain.md                    # Exhaustive 9-stage workflow protocol specification
│   ├── 02_tests_and_build.md                   # Unit test census (95 tests), build commands, coverage
│   ├── 03_limitations_and_warnings.md          # Forensic bugs, rate limits, cookie partitioning, WAF traps
│   ├── 04_future_features.md                   # Stubbed features, Minecraft wiring, legacy JS comparison
│   └── 05_prompt_history.md                    # Key architectural decisions, rationale, git commit history
├── src/
│   ├── main/
│   │   ├── resources/
│   │   │   └── logback.xml                     # Logback config (console & logs/bot.log rolling appender)
│   │   └── kotlin/
│   │       ├── Main.kt                         # Application bootstrap, Koin modules, Kord login
│   │       ├── command/
│   │       │   ├── CommandManager.kt           # Slash command dispatcher and global command registrar
│   │       │   ├── commands/
│   │       │   │   └── PingCommand.kt          # Global slash command: /ping
│   │       │   └── model/
│   │       │       └── CommandInterface.kt     # Command handler interface contract
│   │       ├── config/
│   │       │   └── BotPropertiesManager.kt     # Reads and reloads config.properties
│   │       ├── database/
│   │       │   ├── DatabaseManager.kt          # HikariCP pool setup, SQLite connection, schema migrations
│   │       │   ├── di/
│   │       │   │   └── DatabaseModule.kt       # Koin module registering DatabaseManager & AccountRepository
│   │       │   ├── model/
│   │       │   │   └── RecoveredAccount.kt     # Account entity model with PENDING/SUCCESS/FAILED statuses
│   │       │   └── repository/
│   │       │       ├── AccountRepository.kt    # Account persistence interface
│   │       │       └── SqliteAccountRepository.kt # JDBC implementation executing on Dispatchers.IO
│   │       ├── discord/
│   │       │   └── DiscordLogger.kt            # Embed builder and failure delivery to Discord log channels
│   │       ├── event/
│   │       │   ├── EventManager.kt             # Gateway event listener registry
│   │       │   ├── events/
│   │       │   │   ├── CreateMessageEvent.kt   # ReadyEvent listener: startup logs and recovery trigger button
│   │       │   │   └── RecoveryInteractionEvent.kt # Modal handlers, deferred OTP/alias bridges, failure deduplication
│   │       │   └── model/
│   │       │       └── EventInterface.kt       # Event handler interface contract
│   │       ├── microsoft/
│   │       │   └── recovery/
│   │       │       ├── RecoveryService.kt      # Recovery engine facade, HTTP client factory, context initializer
│   │       │       ├── RecoveryWorkflow.kt     # 9-stage sequence coordinator, timing, persistence
│   │       │       ├── alias/
│   │       │       │   ├── AliasClient.kt      # Cloudflare worker HMAC client, verify endpoint, make primary
│   │       │       │   ├── AliasExceptions.kt  # Custom exceptions: OtcTimeoutException, AliasVerificationFailedException
│   │       │       │   └── AliasRotationResult.kt # Alias rotation outcome data holder
│   │       │       ├── context/
│   │       │       │   └── RecoveryContext.kt  # Shared cross-stage mutable state (tokens, canaries, cookies, proofs)
│   │       │       ├── di/
│   │       │       │   └── RecoveryModule.kt   # Koin module for RecoveryService
│   │       │       ├── model/
│   │       │       │   ├── RecoveryModels.kt   # Serialization DTOs for Microsoft JSON APIs
│   │       │       │   ├── RecoveryResult.kt   # Sealed outcome hierarchy: Success vs Failure
│   │       │       │   └── StageExecution.kt   # Sealed stage transition wrapper: Success vs Failure
│   │       │       ├── stages/
│   │       │       │   ├── RecoveryStageHandler.kt # Stage functional interface & StageListener typealias
│   │       │       │   ├── Stage1Discovery.kt  # Stage 1: login.srf PPFT scrape & GetCredentialType proof discovery
│   │       │       │   ├── Stage2Otp.kt        # Stage 2: GetOneTimeCode dispatch, user OTP submission, __Host-MSAAUTH
│   │       │       │   ├── Stage3Polish.kt     # Stage 3: SA_20MIN elevation, DoSubmit() auto-form & token t extraction
│   │       │       │   ├── Stage4Proofs.kt     # Stage 4: Additional proofs enumeration, encryptedNetId & canary scrape
│   │       │       │   ├── Stage5RecoveryCode.kt # Stage 5: POST /API/Proofs/GenerateRecoveryCode
│   │       │       │   ├── Stage6PasswordReset.kt # Stage 6: ResetPassword.aspx, VerifyRecoveryCode, RecoverUser
│   │       │       │   ├── Stage7Suppression.kt # Stage 7: Sequential fail-closed proof notification disabling
│   │       │       │   ├── Stage8Alias.kt      # Stage 8: AddAssocId, OTC verification, MakePrimary, RemoveAlias
│   │       │       │   └── Stage9Cleanup.kt    # Stage 9: DisableTfa, DeleteDevices, DeleteAppPassword, RemovePasskey
│   │       │       └── util/
│   │       │           ├── MicrosoftHttpClientFactory.kt # Configures OkHttp engine, cookies, and JSON serializers
│   │       │           ├── RecoveryParsers.kt  # String/regex utilities: Unicode unescaping, PPFT, token t, balanced JSON
│   │       │           └── Stage3Parser.kt     # Jsoup parser for DoSubmit auto-forms and hidden input fields
│   │       └── minecraft/
│   │           └── ownership/
│   │               ├── MinecraftOwnershipService.kt # Xbox Live, XSTS, Mojang entitlements & profile service
│   │               ├── MinecraftOwnershipDemo.kt # Standalone CLI demo runner (gradle runDemo)
│   │               ├── di/
│   │               │   └── MinecraftOwnershipModule.kt # Koin module for Minecraft ownership service
│   │               ├── model/
│   │               │   ├── MinecraftOwnershipModels.kt # Entitlement and Xbox Live request/response DTOs
│   │               │   └── MinecraftOwnershipResult.kt # Sealed outcome: Owned, NotOwned, Failure
│   │               └── util/
│   │                   ├── MinecraftHttpClientFactory.kt # HTTP client configured for Xbox and Mojang REST APIs
│   │                   └── XstsErrorMapper.kt  # Maps numeric XSTS error codes to actionable diagnostics
│   └── test/
│       └── kotlin/
│           ├── database/
│           │   └── SqliteAccountRepositoryTest.kt   # 6 tests: CRUD, upsert, schema migration, status tracking
│           ├── discord/
│           │   └── DiscordLoggerTest.kt             # 6 tests: Failure embed construction, string truncation, field clamping
│           ├── event/
│           │   └── events/
│           │       └── RecoveryInteractionEventTest.kt # 8 tests: Failure deduplication, atomic suppression, debug buffering
│           └── microsoft/
│               └── recovery/
│                   ├── AdversarialStressTest.kt     # 13 tests: Cookie partitioning, UAID omission, passkey nulls, timeouts
│                   ├── RecoveryParsersTest.kt       # 13 tests: PPFT regex, Unicode unescaping, password generation, token t
│                   ├── RecoveryServiceTest.kt       # 28 tests: Full 9-stage lifecycle, DoSubmit hops, State 201/206, error codes
│                   ├── alias/
│                   │   └── AliasClientTest.kt       # 11 tests: HMAC generation, worker polling, manual OTC fallback
│                   └── minecraft/
│                       └── ownership/
│                           └── MinecraftOwnershipServiceTest.kt # 10 tests: Xbox auth, XSTS error mapping, entitlements
```
