# Inspect JVM source-line & local-variable debug metadata (#2377)

## Outcome and scope

Read compiler-emitted debug metadata from one caller-selected `.class` file or a
selected JAR entry, so an analyst can judge debugging readiness **before**
attaching a debugger. No Java executes; no source URL is resolved; no live target
is involved. This is static format inspection within existing offline-artifact
authority, not a new runtime provider and not decompilation.

The tool reads only these class-file attributes: `SourceFile`,
`SourceDebugExtension`, `LineNumberTable`, `LocalVariableTable`,
`LocalVariableTypeTable`. Decompiler line numbers are not compiler source
positions and are never substituted for these.

## Inspection contract

Bind every fact to exact identity: class internal name/descriptor, source file
name as declared, major/minor version, and per method the name **plus
descriptor**, bytecode offset, local **slot** and scope range. A method debug
state is reported as `present | partial | stripped | malformed | not-applicable`.
Absent tables, malformed records, partial examination and ambiguous mappings are
distinguished; a reused local slot may denote different variables across scope
ranges and is never collapsed. `SourceDebugExtension` bytes are preserved opaquely with bounded
access; an admitted source-map dialect is interpreted only when established, and
unknown extensions remain opaque rather than guessed.

In a multi-release JAR the requested effective class version is selected
explicitly or its alternatives are reported; metadata from different entries is
never silently combined. Ordering is deterministic: methods sorted by name then
descriptor (stable across recompilation that reorders members), and each
table's entries in their declared (occurrence) order, not re-sorted. The
result returns artifact path/digest/length, class identity, the bound debug
facts, examined-vs-reported `coverage`, and `limitations`. Unresolved values are
explicit — a name whose constant-pool index does not resolve is `null`, and a
table's `presence` is `absent | present | malformed` — never guessed or omitted.
Supplied source bytes are never claimed to match a `SourceFile` name.

## Authority and overlap

Reads the supplied artifact only: no process, network, UI, or mutation effects,
no target acquisition, no foreign-code execution. Debug-metadata identity stays
separate from any decompiler output. Standalone `.class`/JAR inspection is
deliberately independent of the Android/JADX lane (`REA_JADX_MCP_JAR`) and of the
JVM runtime/JDWP proposal (#2376). Parent Java domain: #1558.

## Resource admission

Every length-prefixed structure is bounded against the buffer before allocation;
a declared interface/field/method/attribute count exceeding the remaining bytes
is refused as invalid input (`AnalysisInputError`). Only attributes the reader
consumes are materialised, charged to a shared retained-attribute budget; others
are framed and skipped. A projection (`projectDebugOutput`, reads table headers
and constant-pool indices only) counts entries and the encoded size of every
referenced string, refusing with an `AnalysisResourceConstraintError` before any
entry object is allocated — input bounds alone bound neither the ~50x object
expansion nor a shared long name repeated across entries — and the exact
serialized result is re-checked against the inline output budget. JAR
entry reads are bounded per entry; the archive is admitted once and its digest is
read through that same descriptor. Parsing is linear in examined bytes. A 30 MiB
crafted class with ~8M declared entries is refused in ~1 ms; token usage remains
unmeasured.

## Verification

Owned `javac` fixtures compiled with full `-g` and with `-g:none` (the real
`verify:jvm` lane, cross-checked against `javap`) show the actual difference and
cover overloads, local-slot reuse across scopes, wide (long/double) locals, a
generic method yielding a `LocalVariableTypeTable`, and a multi-release JAR
binding to the selected member. Unit tests cover the framing and decode:
split/merged tables, invalid/out-of-range scope, truncated attributes, the
over-entry pre-count guard, CESU-8 supplementary pairs, `SourceDebugExtension`
opaque preservation, encrypted-member and Mach-O-universal refusals, symlink
rejection, release-without-entry, and already-aborted cancellation. CLI/MCP
parity and advertised-schema validity (kept shallow and dialect-safe, per
#2813/#2832) are exercised. Still owed (see verification.md): unit fixtures for a
JDK-free CLI/MCP workflow and an R8/ProGuard-shaped scrambled-table class.
Independent subagent review before handoff.

Format reference: JVMS class-file attributes, sections 4.7.10–4.7.14 —
https://docs.oracle.com/javase/specs/jvms/se25/html/jvms-4.html
