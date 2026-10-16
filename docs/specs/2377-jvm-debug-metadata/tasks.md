# Tasks

- [x] Confirm scope: static `.class`/JAR inspection, in-scope, no runtime/#2376 overlap.
- [x] Record spec and implementation plan.
- [x] Implement dependency-free class-file framing (bounded, `Result`-based).
- [x] Decode the five debug attributes with absent/malformed/partial/ambiguous modeling.
- [x] Normalize Evidence with deterministic ordering and examined coverage.
- [x] Add application service: local-file and JAR-entry resolution, multi-release
      selection, parse-error mapping to `analysisErrorCore`, bounded reads, provenance.
- [x] Add CLI/MCP contracts, catalog registration, and public workflow tests.
- [x] Add owned `javac` `-g` / `-g:none` fixtures and the verification lane.
- [x] Write the analyst-facing guide; run focused, static, and documentation checks.
- [x] Resolve first-round review findings (split tables, output budget, provider
      catalog, UTF-8 continuation) and the JAR/multi-release second round.
- [x] Resolve second independent (Fable) review: effect-wording gate, pre-count
      entry budget, JAR admit-once/TOCTOU, encrypted + Mach-O refusals, coverage.
- [ ] Remaining follow-ups (see verification.md): JDK-free CLI/MCP workflow test,
      scrambled-table fixture, discoverability surfaces (README/skill/mermaid),
      and the F9–F11 decoder-strictness/ergonomics items.
