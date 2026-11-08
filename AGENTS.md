# AGENTS.md — Project Instructions & Coding Standards

## 0. How to use this file

These are the default rules for new work. When modifying an existing project, inspect it and follow its established architecture, even where that intentionally differs from this file. Do not perform unrelated refactors, migrations, or cleanup unless explicitly requested.

### Requirement levels

- **MUST** / **MUST NOT**: mandatory unless the user explicitly overrides it.
- **SHOULD**: preferred; deviate only when the project or task gives a good reason.
- **MAY**: optional and context-dependent.

### Priority when rules conflict

1. The user's explicit instruction in the current task.
2. Existing project architecture and compatibility requirements.
3. MUST / MUST NOT rules in this file.
4. SHOULD preferences.
5. Generic framework or language conventions.

Do not treat a convention as universal because it appears in one project. Reuse an architectural pattern only when the new project has the same requirements.

## 1. Core principles

1. Fit the existing project and the author's conventions. No generic clean-code rewrites, no speculative abstractions.
2. Make the smallest coherent change that satisfies the request.
3. Verify instead of assuming: existing classes, APIs, config keys, dependencies, versions, and platform support.
4. Never guess a version from training knowledge. Look it up (see §3).
5. Do not touch what was not asked: no unrelated refactors, reformatting, or version bumps.
6. Never claim a build, test, or runtime check passed unless it was actually executed successfully.

## 2. Workflow

### Before editing

1. **MUST** read the relevant source files, build configuration, plugin descriptor, and neighboring implementations.
2. **MUST** identify the language, runtime/API versions, package structure, dependency model, and supported platforms.
3. **MUST** trace how the feature is initialized, how dependencies are obtained, how configuration is accessed, and how messages/errors are handled.
4. **MUST** prefer extending an existing manager, interface, utility, or flow over creating a competing mechanism.
5. **MUST NOT** invent classes, methods, configuration keys, dependencies, or APIs without checking that they exist and fit the project.
6. If an architectural decision is unclear, inspect more examples first. Ask the user only when the ambiguity materially affects the implementation and cannot be resolved from the project.

### While editing

- **MUST** preserve the surrounding file's formatting. Do not reformat unrelated sections.
- **SHOULD** follow the project's existing file/package placement instead of creating a new organizational scheme.
- **MUST** update every connected piece when adding a feature: registration, configuration defaults, message keys/mappings, permissions, metadata, persistence schema, and lifecycle wiring, as applicable.
- **MUST NOT** leave dead code, duplicate message paths, unused dependencies, or half-registered features.
- **MUST NOT** modify generated files, lockfiles, dependency versions, or unrelated configuration unless the task requires it.

### After editing

- **MUST** run the most relevant available build or test task when feasible. If it cannot be run, say so clearly.
- **MUST** inspect the final diff for formatting churn, unrelated edits, missing registrations, and inconsistent naming.
- **MUST** finish with the report described in §14.

## 3. Dependencies and versions

The build files and plugin descriptor are the source of truth for what the project currently uses. Inspect them before changing anything.

### Never guess versions

- **MUST NOT** write a dependency, plugin, API, or toolchain version from memory or training knowledge. Versions, coordinates, and repositories change faster than training data.
- **MUST** look the version up with web search or by fetching official sources: Maven Central, the library's official repository/releases page, official documentation, the Gradle Plugin Portal. Prefer primary sources over blogs, aggregators, or AI summaries.
- If searching is not possible, **MUST NOT** fall back to a guess. Keep the existing version, or ask the user, and state clearly that the version is unverified.

### Adding a dependency

1. **MUST** confirm it is needed: not already covered by the standard library, the platform API, or an existing dependency.
2. **MUST** search for the exact current release and verify the groupId/artifactId, the repository URL, the latest stable version, and that the library is still maintained.
3. **SHOULD** default to the latest stable release. Skip alpha, beta, RC, milestone, and snapshot builds unless the user asks for one or no stable release exists (say so if that is the case).
4. **MUST** check the candidate against the project: JDK/Kotlin/Gradle versions, minimum supported server/API version, transitive conflicts with existing dependencies, shading/relocation needs, and license when relevant.
5. If the latest version is incompatible, **MUST** pick the newest compatible version and explain why in the final report.
6. **MUST** declare it through the project's own mechanism (version catalog, `build.gradle(.kts)`, `pom.xml`, descriptor `depend`/`softdepend`/`libraries`) with the correct scope: compile-only, shaded, or runtime-provided.
7. **MUST** confirm the build resolves it.

### Upgrading a dependency

Upgrade only when the user asks or a concrete requirement demands it. "A newer version exists" is not a reason.

Before changing any version:

1. **MUST** identify the current version (from the build files) and the target version (from search, not memory).
2. **MUST** read the release notes, changelog, and migration guides for every version between the two.
3. **MUST** summarize what differs: new features, bug fixes, security fixes, performance changes, deprecations, removals, breaking changes, and changed minimum requirements (JDK, Kotlin, server API).
4. **MUST** decide whether the upgrade genuinely helps this project: it fixes a bug the project hits, closes a relevant vulnerability, provides an API the task needs, or is required for platform compatibility. If there is no concrete benefit, **MUST NOT** upgrade, and tell the user why.
5. **MUST** assess risk: breaking API changes, behavior changes, and transitive dependency changes. Adapt code only as far as the upgrade requires.
6. **SHOULD** bump one dependency, or one coherent group (for example Kotlin and its Gradle plugin), at a time, then build and test.
7. **MUST** report: current → target version, the changes that matter, the benefit verdict, the risks, and what was verified.

The same process applies to the Kotlin/JDK version, Gradle and its plugins, and the server API version.

### Versions and metadata

- **SHOULD** keep the plugin version consistent across the build configuration, plugin descriptor, generated metadata, and any version-reporting code.
- **SHOULD** use the Bukkit-compatible plugin description/version API when Spigot compatibility is required. Do not rely on Paper-only metadata APIs in cross-platform code.
- **MUST** preserve the project's Java/Kotlin toolchain and target bytecode unless the user requests an upgrade or a dependency requires one.
- **MUST** verify shaded/relocated and runtime-provided libraries in the build configuration and plugin descriptor before changing packaging behavior.

## 4. Architecture and class responsibilities

- **MUST** keep the main plugin class primarily a lifecycle and dependency-initialization coordinator. No feature business logic, SQL, or command-specific behavior there.
- **MUST** keep classes focused on their established responsibility. Reuse existing managers for configuration, messaging, persistence, integrations, and other cross-cutting concerns.
- **SHOULD** use constructor dependency injection for ordinary classes. Pass required dependencies explicitly.
- **MUST NOT** introduce `getInstance()`, static singleton fields, or service-locator patterns when dependencies can be passed through constructors or an existing context object.
- **SHOULD** keep domain/data models independent of Bukkit runtime objects. Prefer `UUID`, strings, numbers, and domain types over storing `Player` or other live server objects.
- **MAY** introduce interfaces, registries, strategies, facades, or context objects when there is a real need: multiple implementations, optional integrations, a stable boundary, or a genuinely unwieldy constructor/API. Do not add abstraction for theoretical extensibility.
- **MUST NOT** create an interface for every class or split a small, cohesive operation across multiple files without a concrete benefit.

## 5. Plugin lifecycle

### Dependency declaration

For Bukkit-style plugins following the InsureInv pattern:

- **SHOULD** declare long-lived components as individual `lateinit var` properties in the main plugin class, with `private set` where other classes need read access but must not replace the instance.
- **SHOULD** let dependent classes read initialized components from the injected main plugin reference when that is the established pattern. Do not add a second global access mechanism.
- **MUST** use constructor injection for classes that need the plugin instance or other dependencies.
- **MUST NOT** access a `lateinit` property before its initialization point.

### Initialization order

- **MUST** initialize dependencies sequentially in an order that respects the dependency graph. Never initialize a component before one it needs.
- **SHOULD** handle platform/runtime prerequisites first: detect the server platform and set up scheduling support before platform-dependent services.
- **SHOULD** initialize `BukkitAudiences` and `ConfigManager` as early as their prerequisites allow. Messaging depends on audiences and configuration; most managers depend on configuration.
- **MUST** initialize `MessageManager` after `ConfigManager` and the audience service it uses.
- **MUST** initialize economy, storage, and other feature managers only after their own prerequisites are ready.
- **MUST** register commands and listeners only after every dependency they consume has initialized successfully.
- **MUST** stop startup cleanly if a critical step fails. Do not register features with missing required services.
- **SHOULD** keep the sequence visible in the main lifecycle method or in clearly ordered helper methods. Avoid reflection-based initialization and unordered dependency containers.

### Shutdown

- **MUST** release resources owned by initialized components: storage connections/pools, coroutine scopes and tasks, audiences, schedulers, and other closeable services.
- **MUST** account for partial startup: check that `lateinit` properties were initialized before using them in `onDisable()`.
- **SHOULD** flush or persist important state before closing storage, using bounded waits where blocking shutdown is necessary.

## 6. Configuration

- **MUST** centralize loading, reload, validation, and typed access in `ConfigManager` (or the project's established equivalent).
- **MUST NOT** scatter raw `plugin.config` lookups across commands, listeners, and feature classes when a manager accessor is appropriate.
- **SHOULD** expose small typed getters: expression-body functions for simple reads, inline fallback values where that matches the surrounding code.
- **MUST** validate required values and clamp values to meaningful bounds when invalid configuration could break behavior.
- **SHOULD** persist configuration changes through the manager's established save flow. Unrelated classes must not write config files directly.
- **MUST** use `kebab-case` for YAML sections and keys unless an existing file establishes a different schema.
- **SHOULD** add useful YAML comments when a value needs explanation. The no-comments rule applies to source code, not to user-facing configuration.

### Prefix configuration

For new Bukkit plugin configurations using this convention, **MUST** provide a `prefix` section with exactly these two settings:

```yaml
prefix:
  text: "<your-prefix>"
  prefix-enabled: true
```

- `prefix.text` holds the formatted prefix; `prefix.prefix-enabled` controls whether it is prepended.
- **MUST** let the centralized message layer apply the prefix. **MUST NOT** rebuild or hardcode it at call sites.
- In an existing project with a different schema (for example `messages.prefix` and `messages.enable-prefix`), **MUST** keep that schema unless the user requests a migration. Do not silently rename or duplicate keys to match this template.

## 7. Messaging and Adventure

- **MUST** implement and use a centralized `MessageManager` (or the project's equivalent) for all player-facing and command-facing messages, including command output.
- **MUST NOT** call `sendMessage` / `Audience.sendMessage` or deserialize MiniMessage ad hoc in commands and listeners when the message manager can do it.
- **MAY** use direct audience output for narrowly scoped non-localized console output, startup banners, or version/build info, when that is an established exception. Keep such exceptions small and intentional.
- **MUST** keep message text in the project's message resource/config files when the project supports configurable or localized messages.
- **SHOULD** centralize prefix application, MiniMessage parsing, placeholder substitution, and sender-specific behavior in the message layer, using the project's existing placeholder helper.
- **MUST NOT** duplicate message formatting logic across commands and listeners.

## 8. Platform compatibility (Spigot / Paper / Folia)

When a plugin must support multiple Bukkit-family platforms:

- **MUST** identify the minimum supported Minecraft/server/API versions, and verify API availability against that minimum instead of assuming a method exists everywhere.
- **MUST** use Adventure Platform Bukkit (`adventure-platform-bukkit`) for audience integration when Spigot support is required, rather than Paper-only native audience/component methods.
- **SHOULD** create the Bukkit audience once at startup and close it on shutdown.
- **MUST** avoid Paper-only APIs in shared code paths. Prefer Bukkit equivalents, or guard Paper-specific code behind a deliberate platform adapter.
- **MUST** use a Folia-compatible scheduler abstraction (such as FoliaLib) when Folia is a target. Do not assume the traditional Bukkit scheduler is safe everywhere.
- **MUST** verify behavior on servers where an optional dependency is absent.
- **SHOULD** keep platform detection and platform-specific behavior behind a small abstraction rather than scattering server-name checks through feature code.
- **MUST NOT** claim compatibility merely because the project compiles against Paper. Check runtime API availability and threading assumptions for each declared target.

## 9. Database and persistence

No project is required to use a single database class or a multi-layer storage abstraction. Choose by actual requirements and preserve the existing design.

- **MUST** inspect the existing persistence architecture first, and reuse its database/storage manager, connection lifecycle, schema, and error-handling conventions.
- **SHOULD** use direct JDBC (`Connection`, `PreparedStatement`, `ResultSet`) for straightforward SQL when that is the project's approach. Do not add an ORM or query builder without an explicit requirement or demonstrated need.
- **MAY** use a storage interface with multiple backends only when the project genuinely supports several storage engines. **SHOULD** keep a single-backend project simple: no strategy/factory/registry hierarchy without a realistic alternative implementation.
- **MUST** pass user-provided and runtime values as `PreparedStatement` parameters. Never concatenate them into SQL.
- **MUST** close JDBC resources reliably, preferably with Kotlin `.use {}`.
- **SHOULD** keep SQL inline at the call site as multiline raw strings with `.trimIndent()` when following the InsureInv style. Use constants only for queries that are genuinely shared or independently managed.
- **SHOULD** put small private mapping/extension functions near the bottom of a storage implementation when they make `ResultSet` conversion clearer and match the project.
- **MUST** respect the database's concurrency model. Do not share non-thread-safe connections across concurrent tasks without synchronization or pooling.
- **MUST** keep blocking database I/O off server-sensitive threads when the platform and feature require it, using the project's coroutine/scheduler bridge rather than a new async mechanism.
- **MUST** handle connection failure, query failure, and shutdown predictably (see §11).

## 10. Commands, listeners, and integrations

- **SHOULD** keep root command routing separate from subcommand implementations when the project uses a subcommand architecture. Place subcommands in the established package and register them through the existing root handler.
- **MAY** pass an immutable context object to subcommands when many share the same runtime dependencies. Do not add one for one or two dependencies, or when the project does not use the pattern.
- **SHOULD** use early returns for invalid sender types, missing arguments, permission failures, unavailable players, and other guard conditions.
- **MUST** respect the platform's threading and event rules (see §8).
- **SHOULD** isolate optional third-party integrations behind provider/adapter classes so core code does not depend directly on optional plugin APIs.
- **MUST** check that an external plugin is present and enabled before using its services.
- **MUST** avoid eager class loading that can cause `NoClassDefFoundError` when optional APIs may be absent. Follow the project's soft-dependency, reflection, or provider-loading mechanism.
- **MAY** use a provider interface and registry when several integrations implement the same capability or fallback ordering is required.

## 11. Errors, logging, and resource safety

- **MUST** use the plugin's logger or the project's logging abstraction. Do not add a second logging framework for ordinary plugin messages.
- **SHOULD** log meaningful lifecycle transitions, selected providers/backends, and actionable failure context without flooding the console.
- **MUST** distinguish fatal initialization failures from optional integration failures. Disable the plugin cleanly when a required subsystem cannot start; let optional integrations fall back when that is the designed behavior.
- **MUST NOT** swallow exceptions when that hides failed operations or risks data loss, including persistence errors.
- **MAY** ignore an exception in a narrowly scoped optional-dependency probe where absence is an expected outcome. Otherwise log enough context to diagnose it.
- **SHOULD** make asynchronous failures observable through logging or the project's error-reporting path.
- **MUST** close resources and cancel owned coroutine scopes/tasks on shutdown.

## 12. Kotlin coding style

### Source comments

- **MUST NOT** add `//`, `/* ... */`, or KDoc comments to Kotlin source files by default. Prefer clear names, straightforward control flow, and small functions.
- Add a source comment only when the user explicitly asks for it, or when a non-obvious constraint cannot reasonably be expressed in code. Keep it short and local.
- This does not apply to YAML configuration comments or documentation such as README/AGENTS files.

### Formatting

- **MUST** use 4 spaces for indentation, never tabs.
- **MUST** put the opening brace on the same line as the declaration/control statement, and the closing brace on its own line.
- **SHOULD** separate properties, methods, and logical sections with one blank line. No consecutive blank lines, and no blank lines at the start or end of class bodies.
- **SHOULD** keep lines around 100–120 characters where practical. Break long parameter lists and method chains when it improves readability.
- **SHOULD** keep imports explicit and organized like the surrounding file. No wildcard imports unless the project clearly uses them in that area.

### Expressions and control flow

- **SHOULD** use expression-body functions for simple getters, accessors, and short calculations:

```kotlin
fun hasCharges(): Boolean = charges > 0
fun getMaxCharges(): Int = config.getInt("economy.max-charges-per-player", 10)
```

- **MUST** declare explicit return types on public and protected functions, including expression-body ones.
- **SHOULD** prefer guard clauses and early returns over deep nesting.
- **SHOULD** use `when` for enum branching, multiple alternatives, and clear value-based branching.
- **SHOULD** use Kotlin null-safety idioms (`?.`, `?:`, `let`) instead of unnecessary null checks and force unwraps.
- **SHOULD** use scope functions by intent: `apply` for configuration, `also` for side effects, `let` for nullable transformations, `use` for resource cleanup.
- **SHOULD** use implicit `it` for simple single-parameter lambdas. Use a named parameter when it clearly helps or when nesting makes `it` ambiguous.
- **SHOULD** inline simple one-use expressions. Introduce a local variable only when an expression is repeated, hard to read, expensive, or a meaningful intermediate value.
- **MUST NOT** over-engineer a small operation or expand concise Kotlin into verbose Java-style boilerplate without a concrete reason.

### Naming

- Classes, interfaces, objects, enum types: `PascalCase`.
- Functions, properties, local variables: `camelCase`.
- Compile-time constants: `SCREAMING_SNAKE_CASE`.
- YAML keys: `kebab-case`. SQL tables and columns: `snake_case`.
- **MUST** follow the naming style already established in the relevant package/file when it differs for a justified reason.
- **SHOULD** use descriptive names for public APIs and domain concepts. Short local names are fine when the meaning is obvious in a small scope.

## 13. Reference patterns from InsureInv (conditional)

Proven in the reference project, but **not** universal requirements:

- `StorageBackend` interface + `StorageManager` + backend implementations: only when multiple persistence backends and fallback are real requirements.
- `EconomyProvider` interface + provider registry: only when several optional economy plugins supply the same capability.
- `CommandContext`: only when many subcommands share a large set of dependencies.
- Private `ResultSet` extension mapper: keeps JDBC row conversion concise and local to a backend.
- `ConcurrentHashMap`, `Mutex`, `@Synchronized`, coroutine dispatchers, scheduler abstractions: each solves a different concurrency problem. Pick the one that fits the data and execution model; do not copy mechanically.
- Translation table between flat command message keys and nested YAML keys: only if the project already uses that scheme. Do not add a mapping layer to a new project without a reason.
- Reflective provider factories: for optional integrations whose classes may be missing at runtime, not for ordinary internal classes.

## 14. Final report

When a coding task is complete, give a concise summary:

- What changed and where.
- Important architectural or configuration changes.
- Dependencies added or upgraded: `name: old → new` (or `new` for additions), the source the version was verified from, and for upgrades, the key changes and why the upgrade was worth it. If a dependency was not upgraded because there was no clear benefit, say so.
- Build/test commands run and their results.
- Anything unverified, compatibility caveats, or decisions still open.

Do not claim tests, builds, or runtime checks passed unless they were actually executed successfully.
