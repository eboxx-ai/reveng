# JVM class-file debug metadata

REA reads compiler-emitted debug metadata from one caller-selected local `.class`
file so an analyst can judge **debugging readiness before attaching a debugger**.
The reader is in-process and dependency-free: it decodes class-file attributes
only, never executes Java, never resolves a source URL, and never claims that
supplied source matches a declared `SourceFile`. Decompiler line numbers are not
compiler-emitted source positions and are never substituted for them.

CLI and MCP share one workflow and return artifact-bound Evidence inline.

## Answer an analyst question

```sh
rea inspect-jvm-debug-metadata /path/Example.class
# Select one class entry inside a JAR:
rea inspect-jvm-debug-metadata /path/app.jar --entry com/example/Service.class
# Select a multi-release override explicitly:
rea inspect-jvm-debug-metadata /path/app.jar --entry com/example/Service.class --release 17
```

The MCP method is `inspect_jvm_debug_metadata`. Pass the absolute local `path`
(a `.class` file, or a `.jar` with `entry`); for a multi-release JAR add
`release` to select an override:

```json
{
  "name": "inspect_jvm_debug_metadata",
  "arguments": {
    "path": "/path/app.jar",
    "entry": "com/example/Service.class",
    "release": 17
  }
}
```

A JAR entry is selected explicitly: an omitted `release` reads the base entry,
and a requested `release` must match a present `META-INF/versions/<N>/` override
or the call is refused with the available versions — metadata is never combined
across versions.

## Interpret the result

The normalized result binds every fact to exact identity:

- `artifact` — the selected local file's `path`, exact-byte `sha256`, and
  `bytes` (the `.class` file, or the `.jar` for a JAR entry). The reader does
  not mutate the selected bytes; `sha256` identifies them, not authenticity or
  the producing compiler.
- `container` — `class-file` or `jar`. `selected_entry` is `null` for a loose
  class file, or the selected `entry`, `release` (null for base), `sha256`, and
  `bytes` of the class bytes read from the JAR.
- `class` — `internal_name` (the JVM binary name from the constant pool, e.g.
  `com/example/Foo`; not decompiler output), `major_version`, `minor_version`.
- `source_file` — `presence` (`present` | `absent` | `malformed`) and the
  declared `name` when present.
- `source_debug_extension` — `presence` and opaque `byte_length`. The bytes are
  preserved but never interpreted; no source-map dialect is parsed.
- `methods[]` — each with `name`, `descriptor`, debugging `state`, and the three
  decoded tables:
  - `line_number_table` — `start_pc` → `line_number` entries.
  - `local_variable_table` — `start_pc`, `length`, `name`, `descriptor`, `slot`,
    and `out_of_range` (the scope lies outside the method's code length).
  - `local_variable_type_table` — as above with a generic `signature`.
  - `reused_slots` — slots that appear in more than one local-variable entry.
    Reuse is legal; a reused slot may denote different variables across disjoint
    scope ranges, so entries are preserved rather than merged.
- `coverage` — method counts per state, derived from examined methods.

### Method debugging state

| `state`          | Meaning                                                            |
| ---------------- | ------------------------------------------------------------------ |
| `present`        | both line and local-variable tables decoded                        |
| `partial`        | one table present, the other absent                                |
| `stripped`       | a body exists but carries neither table (e.g. `javac -g:none`)     |
| `malformed`      | a present table failed to decode fully; recovered entries are kept |
| `not-applicable` | no `Code` attribute (native/abstract, or no body)                  |

A table whose declared entry count exceeds its bytes is reported `malformed` with
the entries recovered before the short read. When a later sibling inside the
same `Code` attribute is malformed, tables framed before it are kept and tables
that were never reached are `unread` (unknown), not `absent`; absent, malformed, partial, and
ambiguous (reused-slot) cases stay distinct and are never collapsed into
"absent".

## Scope and limits

Static class-file inspection only. No Java executes; no source URL is resolved;
supplied source bytes are never claimed to match a `SourceFile` name. Debug
metadata identity stays separate from any decompiler output. Standalone `.class`
inspection is independent of the Android/JADX lane and of the JVM runtime
(JDWP) proposal. A malformed or truncated class file is reported through the
tagged error algebra rather than throwing. A single class file far over the
input budget is refused before allocation. Only the attributes this reader
consumes are materialised (others are framed and skipped), under a shared
budget. Before any entry is built, a projection counts debug-table entries and
the encoded size of every constant-pool string each entry references, so a class
with too many entries, or whose shared long names would expand past the inline
output budget, is refused without building the report; the exact serialized
size is checked again afterwards. A local-variable scope whose `[start_pc, start_pc+length)`
lies outside the method's code length is surfaced as declared and flagged
`out_of_range: true`, never silently corrected.

Verified by the `verify:jvm` real lane, which compiles owned `javac` fixtures
with `-g` and `-g:none` and cross-checks the decoded facts against `javap` —
`SourceFile`, `LineNumberTable` entry counts, and `LocalVariableTable` /
`LocalVariableTypeTable` presence and method descriptors (not individual
pc→line pairs or slot scopes) — then exercises the CLI and MCP in parity against
real application bytecode.
