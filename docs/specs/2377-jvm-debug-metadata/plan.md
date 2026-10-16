# Plan

1. Confirm scope and overlap: static `.class`/JAR inspection only; no runtime
   (#2376), decompilation, or bytecode edit. Complete open/closed PR search.
2. Implement a dependency-free, bounded class-file reader in the domain layer,
   returning framed facts via `Result` and modeling malformed input as tagged
   errors rather than exceptions.
3. Decode `SourceFile`, `SourceDebugExtension`, `LineNumberTable`,
   `LocalVariableTable`, `LocalVariableTypeTable`; preserve partial facts and
   distinguish absent, malformed, partial, and ambiguous (reused-slot) cases.
4. Normalize Evidence with deterministic ordering and examined coverage.
5. Add the shared application service (local-file and JAR-entry resolution,
   multi-release selection, parse-error mapping) and strict input/output
   contracts; register an additive `inspect_jvm_debug_metadata` CLI/MCP tool
   with a shallow, dialect-safe schema.
6. Add owned `javac` `-g`/`-g:none` fixtures and documentation; validate
   malformed/multi-release/cancellation cases; run checks, independent review,
   repair findings, and rerun affected checks.
