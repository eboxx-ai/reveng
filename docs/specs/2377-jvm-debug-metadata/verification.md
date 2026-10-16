# Verification

Verified base: fork `FerroLx/rea`, branch `feat/2377-jvm-debug-metadata` off
upstream `main` at 26525706f.

## Domain core (landed)

- Focused domain tests: 3 files / 15 tests passed
  (`javaClassFile.test.ts` 6, `javaDebugMetadata.test.ts` 7,
  `javaDebugMetadataEvidence.test.ts` 2).
- Real-toolchain sanity check: `javac 25.0.4` compiled an owned `Example.java`
  with `-g` and `-g:none`. The parser → decoder → Evidence pipeline reported, on
  the real artifacts:
  - `-g`: `SourceFile = Example.java`; `compute(IJ)I` state `present` with 3
    `LineNumberTable` entries (source lines 3/4/5) and locals `this,a,b,x,i`
    name-resolved; `<init>` `present`.
  - `-g:none`: `SourceFile` absent; both methods `stripped`; coverage tally
    `{present:0, stripped:2}`.
    (Validation used a throwaway fixture; in-repo owned fixtures land with the
    verification-lane task.)
- `oxlint` on `src/domain/jvm/`: 0 errors, 0 warnings. `tsc --noEmit`: no errors
  in the new files. `verify:test-discovery`: all test files discovered once.

## Application / contract / CLI (landed)

- Service tests (19 total with the domain core): local-file inspection,
  relative-path rejection, unsupported-target and missing-file mapping.
- `inspect_jvm_debug_metadata` tool + `inspect-jvm-debug-metadata` CLI wired into
  composition, server, catalog, effect audit, and product-catalog family.
- MCP advertised-schema validity, CLI/MCP Evidence parity, and target-content
  provenance conformance pass; input schema is shallow and dialect-safe.

## Real-toolchain lane (landed)

`npm run verify:jvm` (JDK 25) compiles owned `javac` fixtures with `-g` and
`-g:none` — overloads, wide long/double locals, and a generic method that yields
a `LocalVariableTypeTable` — then cross-checks every decoded fact against
`javap` (SourceFile, LineNumberTable entry count, LocalVariableTable and
LocalVariableTypeTable presence, method descriptors), exercises the compiled CLI
and stdio MCP in Evidence parity, validates a real third-party JAR class
(fontbox/pdfbox when present), and asserts the unsupported-target and
truncated-input error surfaces. 10 cases pass; the reader never mutates the
selected bytes. Skips cleanly when no JDK is present.

## Independent review (three angles)

Three independent reviews (correctness/spec, security/resource/scope,
architecture/conventions) ran against the branch. Confirmed fixed:

- MAJOR — split (multiple) `LineNumberTable` / `LocalVariableTable` /
  `LocalVariableTypeTable` attributes are now merged into one table (JVMS
  §4.7.12–14), not truncated to the first; covered by a decode test.
- MAJOR — the projected result is now bounded by an 8 MiB inline output budget
  (`AnalysisResourceConstraintError`), mirroring the Go/Rust readers; covered by
  a service test.
- MAJOR — `JVM_PROVIDER_IDENTITY` is now surfaced in the generated provider
  catalog (`providers[]` attributes `inspect_jvm_debug_metadata`).
- MINOR — modified-UTF8 continuation bytes are validated (`invalid-utf8` on a
  malformed sequence); the dead `budget-exceeded:"constant-pool"` variant is
  removed.

The reviews verified correct: modified-UTF8 (including CESU-8 supplementary
pairs), constant-pool two-slot rule, Code-header skip, table strides/field
order, projection, layering, reuse, effect audit, and the deferral seam.

## JAR entry + multi-release (landed)

`entry` selects one class member from a `.jar` (read through the shared
`ZipArtifactReader`), and `release` selects a `META-INF/versions/<N>/` override.
Selection is explicit and non-combining: an omitted release reads the base; a
requested release must match a present override or the call is refused with the
available versions (`resolveJarSelection`, unit-tested). The JAR's digest is
streamed (`hashStableFile`, bounded by `archiveBytes`); the class entry is read
bounded by `inputBytes`. The subject is the JAR (`format: "zip"`) and the result
carries `container` + `selected_entry`. `verify:jvm` now builds a real
multi-release JAR (base at release 11, override at 17) and asserts base vs
explicit-17 selection (distinct SHA), absent-release refusal, and missing-entry
error, through the CLI and MCP — 16 cases total.

Out-of-range scope validation against `code_length` landed earlier (flagged
`out_of_range`, raw values preserved).

## Second independent review — JAR/multi-release + out-of-range (three angles)

A second three-angle review ran against the JAR/multi-release and out-of-range
changes. Confirmed fixed:

- MAJOR — the `Multi-Release: true` manifest attribute was not checked, so
  `META-INF/versions/<N>/` entries were honored even on a plain JAR where the
  runtime ignores them. The provider now reads the main manifest; versioned
  selection on a non-multi-release JAR is refused, and versioned directories are
  restricted to integers `>= 9` with no leading zeros.
- MAJOR — duplicate ZIP members at one entry/release were silently collapsed
  (last-wins) while selection reasoned about the first. Duplicate members at the
  selected entry/release are now refused as an ambiguous identity.
- MAJOR — `release` without `entry` was silently ignored yet recorded in
  Evidence. The input schema now rejects that combination at the shared boundary.
- MINOR — `scopeOutOfRange` start boundary corrected to `>=` (JVMS: start_pc <
  code_length); CLI `--release` uses `z.coerce.number().int().nonnegative()`.
- A non-JDK adapter test (`JvmClassFileProvider.test.ts`) builds JARs in-process
  with `@zip.js` and covers base/explicit-release/absent-release/missing-entry/
  non-multi-release/loose-with-entry, so the JAR path has coverage without a JDK.

The reviews verified correct: `resolveJarSelection` (exact match, never nearest;
explicit, non-combining), `classifyJarEntry` near-miss rejection, `#readEntryBytes`
sizing and bomb-bound, subject identity, merged repeatable tables, layering,
contract extension, and effect-audit honesty.

## Third review — usability and decoder strictness (landed)

A fourth-angle pass (architecture/security/correctness/usability) surfaced three
small items, all fixed:

- USABILITY — a `.jar` selected without `entry` previously failed as `bad-magic`
  ("not a class file"). The provider now detects the ZIP signature and returns an
  `AnalysisUnsupportedTargetError` whose remediation points at `entry` (and
  `release`) selection.
- USABILITY — a requested `entry` is normalized once at the JAR boundary
  (`normalizeJarEntryPath`: backslashes → `/`, leading slashes stripped) so a
  caller-supplied `\com\example\Foo.class` or `/com/...` resolves to the internal
  member path; the canonical form is what `selected_entry.entry` records.
- CORRECTNESS — modified-UTF8 decoding now rejects a stray continuation byte
  (`0x80–0xbf`) used as a two-byte lead, while still accepting the legal
  `0xc0 0x80` encoding of U+0000. Covered by two new domain tests.

Unit/service suite was 40 tests (6 files) at this point; `verify:jvm` 16 cases.
`tsc --noEmit` clean; `oxlint` reports only the pre-existing non-blocking
`max-params` warning on `#selectJarMember`. (The Fable-review section below
raises the suite to 53 tests in 7 files.)

## Real-artifact exercise via CLI and live MCP (landed)

Ran the built CLI and the live stdio MCP server against real on-disk artifacts
(not fixtures):

- `netty-handler-4.1.93.Final.jar` → `ChannelTrafficShapingHandler.class`: 10
  methods, all `present`, `SourceFile ChannelTrafficShapingHandler.java`.
  Cross-checked against `javap -v`: 10 `LineNumberTable` + 10 `LocalVariableTable`
  blocks — exact match. CLI and MCP returned byte-identical Evidence (same entry
  SHA-256, coverage).
- `gson-2.11.0.jar` (real `Multi-Release: true`): base `Gson.class` selects
  `release:null`; `module-info.class` with no release is refused (base absent,
  available `[9]`); `--release 9` selects the versioned override
  (`internal_name module-info`); `--release 11` is refused. Same over MCP.
- Real APKs from the Downloads folder (31–152 MiB ZIPs): selecting one without an
  `entry` returns `unsupported_target` steering the caller to member selection;
  `--entry classes.dex` is refused as not a class file; a missing member is a
  `not-found` input error. Verified over both CLI and MCP.

This exercise exposed a real defect in the first usability fix: an archive larger
than the 32 MiB class-file budget (most APKs) was rejected as oversized _before_
the ZIP magic could be examined, so the caller saw "select a smaller artifact"
instead of the member-selection hint. Fixed by classifying on a bounded magic
peek (`peekArtifactMagic`, leading bytes only, independent of total size) before
admitting the file under the class-file budget; covered by new adapter tests.

## Second independent (Fable) review — resolved (landed)

A full independent review on the Fable model ran against the branch and the
spec/plan. Fixed in commits on this branch:

- BLOCKING — the contract effect-wording gate (`toolEffects.test.ts`) failed:
  "No Java executes" matches the execution-wording pattern but the tool was not
  in `EXECUTION_WORDING_EXCEPTIONS`. Added (an earlier verification claim that
  the effect audit was green had not run this specific gate — now it does).
- RESOURCE (was "pending" below) — decoded entries are now capped by a cheap
  pre-count (`countDebugEntries`) and `maxDebugEntries` before any entry object
  is allocated; a 30 MiB crafted class with ~8M declared entries is refused in
  ~1 ms (previously ~1.5 GiB RSS). The "bounded before allocation" claim is now
  true, not aspirational.
- IDENTITY (was "pending" below) — the JAR is admitted once via
  `openRegularFile(symlinks:"reject")`; members and the digest are read through
  that one descriptor (`hashStableRootArtifactHandle`), re-validated at the end,
  so the TOCTOU window is closed and the symlink policy is consistent. The hash
  runs only after selection, so refusals skip the full-archive hash.
- An encrypted matching member is refused as unavailable-not-absent; a Mach-O
  universal binary (shared `0xCAFEBABE`) is steered to `inspect_macho`.
- Coverage: added unit tests for encrypted members, the Mach-O steer, symlink
  rejection, release-without-entry, already-aborted cancellation, CESU-8
  supplementary pairs, and the over-entry pre-count guard.
- Docs truthed up: spec states/ordering/unknowns/bounds wording; tasks.md status.

Unit/service suite is now 53 tests (7 files); `verify:jvm` 16 cases.

## Still owed (follow-ups, not blocking)

- A JDK-free CLI/MCP workflow test (e.g. `localToolContracts` pathRequests plus
  a boundary MCP case) so CI without a JDK still exercises the tool end to end.
- Real-lane fixtures for a truncated-table and an R8/ProGuard scrambled-table
  class (unit-covered today).
- Discoverability surfaces (README capability row, reverse-engineer-anything
  skill source, `architecture.mermaid`) — F8.
- F9–F11 decoder-strictness and ergonomics one-liners (SourceFile length check,
  duplicate single-attribute → malformed, HotSpot-reject parity, a `detail`
  summary mode).
- `npm run check:pr` and full module-boundary/architecture guards at PR time.
  `docs:check` currently fails only on a pre-existing, unrelated `README_tr`
  link drift.

## Limits

No Java executes; no source URL resolved; supplied source bytes are never
claimed to match a `SourceFile`. Debug-metadata identity stays separate from any
decompiler output. Token usage and peak process-family memory unmeasured.
Real-toolchain validation so far covers Linux + JDK 25 only.
