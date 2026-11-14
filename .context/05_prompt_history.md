# 05_prompt_history.md — Key Architectural Decisions & Engineering Log

## 1. Executive Summary

This document records the foundational architectural decisions, engineering trade-offs, and design rationales made during the evolution of the `qh-bot` platform. Each decision is linked to its underlying operational driver, git commit reference, and verified impact on stability, security, and performance.

---

## 2. Core Architectural Decisions

### Decision 1: Monolith God Class Deconstruction into Clean Architecture Domain Stages
- **Git Commit Reference:** `a50a7b8` (*"refactor: decompose RecoveryService into domain stages and RecoveryWorkflow"*)
- **Context & Problem:**
  Early versions of the bot centralized the entire 9-stage Microsoft recovery workflow inside a single monolithic class (`RecoveryService.kt`) exceeding 1,200 lines of code. This structure introduced severe architectural liabilities:
  1. *Tight Coupling & State Leakage:* Cross-stage state (e.g. `uaid`, canaries, tokens, cookies) was manipulated via unstructured local variables, causing unexpected mutations across stage boundaries.
  2. *Testing Fragility:* It was impossible to unit test individual stage transitions (such as Stage 3 session polish or Stage 6 password reset) without simulating the entire multi-stage chain.
  3. *Unclear Error Attribution:* Identifying which specific endpoint or header caused a failure required parsing monolithic log outputs.
- **Architectural Solution:**
  The recovery engine was decomposed into a modular Clean Architecture pattern:
  - **`RecoveryContext`:** A structured, mutable session data container that encapsulates the lifetime of a recovery attempt (HTTP client, cookie storage, UAID, canaries, credentials, and registered proofs).
  - **`RecoveryStageHandler`:** A single-method functional interface implemented by each stage:
    ```kotlin
    fun interface RecoveryStageHandler {
        suspend fun execute(context: RecoveryContext): StageExecution
    }
    ```
  - **Dedicated Stage Classes:** 9 focused domain handlers (`Stage1Discovery` through `Stage9Cleanup`), each containing only the HTTP requests, parsers, and error handling for its step.
  - **`RecoveryWorkflow`:** A linear pipeline coordinator managing sequential execution, bounded delays (`stageDelayMs`), error halts, and persistence.
  - **`RecoveryService`:** A lightweight entry-point facade responsible for instantiating the HTTP client, cookie jar, and context.
- **Engineering Outcome:**
  Each stage is independently unit-testable using Ktor's `MockEngine`. Network simulation, adversarial edge cases, and parser tests now achieve complete isolation, with zero state contamination between stages.

---

### Decision 2: Cloudflare Worker Integration with HMAC-SHA256 Authentication & Fallback
- **Component:** `microsoft.recovery.alias.AliasClient.kt`
- **Context & Problem:**
  Rotating the primary sign-in alias using a custom domain (e.g. `@qhuyy.tech`) requires receiving a 6-digit One-Time Code sent by Microsoft to that address. Because the bot runs as a client application and does not host an inbound SMTP mail transfer agent, an external Cloudflare Worker (`https://qh-bot.qhuyy.tech`) intercepts incoming emails for the domain and stores the latest OTC.
  Exposing an unauthenticated public HTTP endpoint to fetch recovery codes would create a critical security vulnerability and allow unauthorized code interception or replay attacks.
- **Architectural Solution:**
  1. *HMAC-SHA256 Authentication:* Outbound worker requests require a cryptographic signature computed over the alias and current Unix timestamp:
     $$\text{signature} = \text{HMAC-SHA256}( \text{key} = \text{SHARED\_SECRET}, \text{data} = "\$alias:\$timestamp" )$$
  2. *Replay Protection:* The worker enforces a strict timestamp expiration window on incoming requests:
     ```http
     GET /get-otc?email={alias}&timestamp={timestamp}&signature={signature}
     ```
  3. *Operator Fallback via Discord Modals:* If `SHARED_SECRET` is not configured, if the worker times out, or if the operator is using an external domain, the bot automatically engages the `aliasOtcProvider` bridge:
     - Prompts the operator directly via an interactive Discord modal.
     - Accepts either the 6-digit OTC code or the complete Microsoft verification URL (parsed via `AliasClient.extractOtcToken`).
- **Engineering Outcome:**
  Guarantees cryptographic integrity and replay resistance during automated OTC polling, while ensuring operational continuity even if the external worker is unreachable.

---

### Decision 3: Failure-Only Discord Logging & Atomic Deduplication
- **Git Commit Reference:** `598c557` (*"feat(discord): streamline recovery logging to single detailed failure or final result"*)
- **Context & Problem:**
  Originally, the bot updated Discord channels after every single stage. Because the workflow involves 9 stages, intermediate verification steps (`2b`), and diagnostic HTML dumps (`3-debug`, `8-debug`), rapid message creation and channel edits quickly hit Discord REST API rate limits (HTTP 429 Too Many Requests). This resulted in unacknowledged interaction errors, gateway thread delays, and cluttered operational channels.
- **Architectural Solution:**
  1. *Intermediate Success Suppression:* Successful stage completions log strictly to local SLF4J / Logback files (`logs/bot.log`). Zero Discord API requests are dispatched during normal execution.
  2. *In-Memory Debug Buffering:* Stages `3-debug` and `8-debug` store raw diagnostic data (such as HTML snippets and HTTP request parameters) in memory via an `AtomicReference<String?>`.
  3. *Atomic Single-Failure Delivery:* An `AtomicBoolean` (`failureEmitted.compareAndSet(false, true)`) ensures that **exactly ONE** failure embed is emitted to the Discord log channel upon any error:
     - Bundles the failed stage name, failure reason, and attached debug context.
     - Subsequent errors in cleanup or retry routines are suppressed from Discord emission.
  4. *Embed Character Boundary Clamping:* `DiscordLogger.buildFailureEmbed` strictly enforces Discord embed character limits (title $\le 256$, description $\le 4096$, field value $\le 1024$, total $\le 6000$) by safely truncating oversized debug strings.
  5. *Final Result Delivery:* Upon complete success across all 9 stages, a single rich credentials embed (`sendFinalResult`) is posted to `notiChannelId`.
- **Engineering Outcome:**
  Completely eliminated Discord HTTP 429 rate limit exceptions, reduced gateway traffic, and ensured operators receive rich, actionable diagnostic data only when a failure requires investigation.

---

### Decision 4: Single-Connection SQLite Pooling with Dynamic Migrations & Idempotency
- **Components:** `DatabaseManager.kt`, `SqliteAccountRepository.kt`, `RecoveredAccount.kt`
- **Context & Problem:**
  The bot requires local persistence to track recovered accounts, record credentials, and support resumption. However:
  1. *SQLite File Lock Contention:* SQLite is an embedded file-based database. Using standard multi-connection pools frequently causes `SQLITE_BUSY` database lock errors under concurrent coroutine access.
  2. *Schema Evolution:* Early database schemas lacked `status` and `fail_reason` columns, causing SQL errors when querying legacy database files.
  3. *Accidental Re-Runs:* Repeatedly running recovery workflows against accounts that have already been secured triggers Microsoft fraud detection heuristics and risks permanent account bans.
- **Architectural Solution:**
  1. *Single-Connection HikariCP Pool:* HikariCP is configured with `maximumPoolSize = 1`:
     - Eliminates file lock contention while preserving connection reuse and leak detection.
     - All JDBC operations are dispatched through `Dispatchers.IO`.
  2. *In-Place Schema Migrations:* At startup, `DatabaseManager.ensureColumnExists` queries `PRAGMA table_info(recovered_accounts)`. If required columns (`status`, `fail_reason`) are absent, it executes `ALTER TABLE ADD COLUMN` in-place without data loss.
  3. *Idempotent Execution Guard:* In `RecoveryInteractionEvent.prepareRecoveryAccount`, the bot checks `accountRepository.getAccountByOriginalEmail(email)`. If the account status is already `SUCCESS`, the workflow is blocked immediately with an advisory message to protect the account from Microsoft risk penalties.
- **Engineering Outcome:**
  Delivers a zero-maintenance, self-migrating embedded persistence layer that ensures concurrency safety and protects managed accounts from inadvertent rate-limiting.
