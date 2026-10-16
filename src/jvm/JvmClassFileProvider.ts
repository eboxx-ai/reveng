import { createHash } from "node:crypto";

import { createAnalysisExecution } from "../application/AnalysisProvider.js";
import type { ExecutionOptions } from "../application/AnalysisProvider.js";
import type {
  JvmDebugMetadataExecution,
  JvmDebugMetadataPort,
} from "../application/jvm/JvmDebugMetadataPort.js";
import {
  ArtifactReaderFailure,
  type ArtifactEntry,
} from "../artifacts/ArtifactReader.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { ZipArtifactReader } from "../artifacts/ZipArtifactReader.js";
import {
  peekArtifactMagic,
  readStableArtifact,
} from "../artifacts/readStableArtifact.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
  AnalysisUnsupportedTargetError,
} from "../domain/analysisErrorCore.js";
import { parseJavaClassFile } from "../domain/jvm/javaClassFile.js";
import { projectDebugOutput } from "../domain/jvm/javaDebugMetadata.js";
import {
  buildJavaDebugMetadataResult,
  type InspectJvmDebugMetadataInput,
  type JavaDebugMetadataResult,
} from "../domain/jvm/javaDebugMetadataReport.js";
import { err, ok, type Result } from "../domain/result.js";
import { hashStableRootArtifactHandle } from "../artifacts/inventory/hashStableRootArtifact.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import {
  openRegularFile,
  RegularFileAdmissionFailure,
} from "../filesystem/RegularFile.js";
import { OwnedFileHandle } from "../filesystem/OwnedFileHandle.js";
import {
  classifyJarEntry,
  normalizeJarEntryPath,
  resolveJarSelection,
} from "./jarClassEntry.js";
import { JVM_LIMITS, JVM_PROVIDER_IDENTITY } from "./JvmClassFileRelease.js";
import { jvmClassFileFailure, mapParseError } from "./jvmFailures.js";

const OPERATION = "inspect_jvm_debug_metadata";

const sha256 = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");

/** Local-file-header, empty-archive, and spanned signatures all open with "PK". */
const looksLikeZip = (bytes: Uint8Array): boolean =>
  bytes.length >= 2 && bytes[0] === 0x50 && bytes[1] === 0x4b;

/** The smallest class-file major version (JDK 1.1); nothing valid is lower. */
const MIN_CLASS_MAJOR_VERSION = 45;

/**
 * 0xCAFEBABE is both the class-file magic and the Mach-O universal (fat) magic.
 * A fat header's bytes 4-7 are `nfat_arch` (a small count), so a u2 at offset 6
 * below the smallest class major version means this is a Mach-O universal
 * binary, not a class file.
 */
const looksLikeMachOUniversal = (bytes: Uint8Array): boolean =>
  bytes.length >= 8 &&
  bytes[0] === 0xca &&
  bytes[1] === 0xfe &&
  bytes[2] === 0xba &&
  bytes[3] === 0xbe &&
  ((bytes[6]! << 8) | bytes[7]!) < MIN_CLASS_MAJOR_VERSION;

/**
 * A JAR is multi-release only when its main manifest section carries
 * `Multi-Release: true` (JAR File Specification). Otherwise META-INF/versions
 * entries are inert resources the runtime never loads. Parses only the main
 * section (up to the first blank line), honoring line continuations.
 */
const isMultiReleaseManifest = (bytes: Uint8Array): boolean => {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  } catch {
    return false;
  }
  const logical: string[] = [];
  for (const line of text.split(/\r\n|\r|\n/)) {
    if (line === "") break; // end of the main section
    if (line.startsWith(" ") && logical.length > 0)
      logical[logical.length - 1] += line.slice(1); // value continuation
    else logical.push(line);
  }
  for (const attribute of logical) {
    const colon = attribute.indexOf(":");
    if (colon < 0) continue;
    if (attribute.slice(0, colon).trim().toLowerCase() === "multi-release")
      return (
        attribute
          .slice(colon + 1)
          .trim()
          .toLowerCase() === "true"
      );
  }
  return false;
};

const execution = (
  result: JavaDebugMetadataResult,
  path: string,
  subjectSha256: string,
  format: "file" | "zip",
): JvmDebugMetadataExecution =>
  createAnalysisExecution(result, JVM_PROVIDER_IDENTITY, {
    subject: { path, format, sha256: subjectSha256 },
    locations: [{ kind: "artifact-path", path }],
    limitations: result.limitations,
  });

/** Read exactly the selected class-file bytes and decode compiler-emitted debug metadata. */
export class JvmClassFileProvider implements JvmDebugMetadataPort {
  /** Handles whose close failed stay owned here and are retried by `close()`. */
  readonly #resources = new ArtifactResourceScope();

  /** Retry retained cleanup without discarding handles that still cannot close. */
  async close(): Promise<void> {
    try {
      await this.#resources.close();
    } catch (cause: unknown) {
      const cleanup =
        cause instanceof ArtifactReaderFailure ? cause.cleanup : undefined;
      throw new ProviderCleanupError(
        JVM_PROVIDER_IDENTITY.id,
        cleanup?.resources ?? ["artifact-resources"],
        {
          reason:
            cleanup?.reason ??
            (cause instanceof Error ? cause.message : String(cause)),
        },
        { operation: OPERATION, cause },
      );
    }
  }

  async inspect(
    input: InspectJvmDebugMetadataInput,
    options?: ExecutionOptions,
  ): Promise<Result<JvmDebugMetadataExecution, AnalysisError>> {
    try {
      if (options?.signal?.aborted)
        return err(new AnalysisCancelledError(OPERATION));
      return await this.#resources.run(() =>
        input.entry === undefined
          ? this.#inspectClassFile(input, options)
          : this.#inspectJarEntry(
              input.path,
              normalizeJarEntryPath(input.entry),
              input,
              options,
            ),
      );
    } catch (cause: unknown) {
      return err(jvmClassFileFailure(cause, input.path, options?.signal));
    }
  }

  async #inspectClassFile(
    input: InspectJvmDebugMetadataInput,
    options?: ExecutionOptions,
  ): Promise<Result<JvmDebugMetadataExecution, AnalysisError>> {
    // Classify by magic before admitting the whole file under the class-file
    // byte budget: an archive (most APKs/JARs exceed that budget) must be
    // steered to `entry` selection, not rejected as oversized or "not a class
    // file". The peek reads only the leading bytes, regardless of total size.
    const magic = await peekArtifactMagic(
      input.path,
      8,
      options?.signal,
      undefined,
      this.#resources,
    );
    if (looksLikeZip(magic))
      return err(
        new AnalysisUnsupportedTargetError(
          OPERATION,
          input.path,
          "The selected file is a ZIP/JAR archive, not a single .class file.",
          {
            remediationAction:
              "Pass entry to select a class member inside the JAR, e.g. entry=com/example/Foo.class (and release for a multi-release override).",
          },
        ),
      );
    if (looksLikeMachOUniversal(magic))
      return err(
        new AnalysisUnsupportedTargetError(
          OPERATION,
          input.path,
          "The selected file begins with 0xCAFEBABE but its version is too small for a class file; this is a Mach-O universal (fat) binary.",
          {
            remediationAction:
              "Use inspect_macho for Mach-O binaries; this tool reads JVM .class files.",
          },
        ),
      );
    const selected = await readStableArtifact(
      input.path,
      JVM_LIMITS.inputBytes,
      options?.signal,
      undefined,
      this.#resources,
    );
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const parsed = parseJavaClassFile(selected.bytes, {
      retainedAttributeBudget: JVM_LIMITS.maxDebugEntries,
    });
    if (!parsed.ok) return err(mapParseError(parsed.error, input.path));
    const tooMany = this.#rejectIfTooManyEntries(parsed.value, input.path, [
      input.path,
    ]);
    if (tooMany) return err(tooMany);
    const result = buildJavaDebugMetadataResult(parsed.value, {
      path: input.path,
      sha256: selected.sha256,
      bytes: selected.bytes.length,
    });
    const tooLarge = this.#rejectIfOversized(result, input.path);
    if (tooLarge) return err(tooLarge);
    return ok(execution(result, input.path, selected.sha256, "file"));
  }

  async #inspectJarEntry(
    jar: string,
    entry: string,
    input: InspectJvmDebugMetadataInput,
    options?: ExecutionOptions,
  ): Promise<Result<JvmDebugMetadataExecution, AnalysisError>> {
    // Admit the archive once with a no-follow descriptor, and read both its
    // members and its digest through that same descriptor, so the Evidence
    // sha256 identifies exactly the bytes a member was read from (closing the
    // former hash/read TOCTOU) and the symlink policy is consistent.
    let handle;
    try {
      handle = await openRegularFile(jar, {
        symlinks: "reject",
        signal: options?.signal,
      });
    } catch (cause: unknown) {
      // Admission failed and its descriptor close failed too: keep that owner
      // so a later close() retries it instead of leaking the descriptor.
      if (cause instanceof RegularFileAdmissionFailure)
        await this.#resources.release({
          kind: "file-handle",
          resource: jar,
          handle: cause.owner,
        });
      throw cause;
    }
    const owner = new OwnedFileHandle(handle);
    try {
      const initial = await handle.stat();
      if (initial.size > JVM_LIMITS.archiveBytes)
        return err(
          new AnalysisResourceConstraintError(
            OPERATION,
            "file-size",
            `Selected JAR exceeds ${String(JVM_LIMITS.archiveBytes)} bytes: ${jar}`,
            { maximum_archive_bytes: JVM_LIMITS.archiveBytes },
          ),
        );
      const reader = new ZipArtifactReader(
        jar,
        "zip",
        JVM_LIMITS.archiveMetadataBytes,
        { handle, initial },
      );
      try {
        const selected = await this.#selectJarMember(
          reader,
          entry,
          input.release,
          jar,
          options?.signal,
        );
        if (!selected.ok) return selected;
        if (options?.signal?.aborted)
          return err(new AnalysisCancelledError(OPERATION));
        const classBytes = await this.#readEntryBytes(
          reader,
          selected.value.member,
          options?.signal,
        );
        const parsed = parseJavaClassFile(classBytes, {
          retainedAttributeBudget: JVM_LIMITS.maxDebugEntries,
        });
        if (!parsed.ok) return err(mapParseError(parsed.error, jar));
        const tooMany = this.#rejectIfTooManyEntries(parsed.value, jar, [
          jar,
          entry,
        ]);
        if (tooMany) return err(tooMany);
        // Hash only after a member is selected and parsed: a refused call never
        // pays the full-archive (up to 512 MiB) digest.
        const jarDigest = await hashStableRootArtifactHandle(
          jar,
          handle,
          initial,
          options?.signal,
        );
        const result = buildJavaDebugMetadataResult(
          parsed.value,
          { path: jar, sha256: jarDigest.sha256, bytes: jarDigest.bytes },
          {
            container: "jar",
            selectedEntry: {
              entry,
              release: selected.value.release,
              sha256: sha256(classBytes),
              bytes: classBytes.length,
            },
          },
        );
        // The ZIP reader owns member-name interpretation; keep its notes (e.g.
        // an omitted leading "./") so the archive's own name stays visible.
        const withMemberNotes =
          selected.value.member.limitations.length === 0
            ? result
            : {
                ...result,
                limitations: [
                  ...result.limitations,
                  ...selected.value.member.limitations,
                ],
              };
        const tooLarge = this.#rejectIfOversized(withMemberNotes, jar);
        if (tooLarge) return err(tooLarge);
        return ok(execution(withMemberNotes, jar, jarDigest.sha256, "zip"));
      } finally {
        await this.#releaseOrRetain({
          kind: "reader",
          resource: jar,
          reader,
        });
      }
    } finally {
      await this.#releaseOrRetain({
        kind: "file-handle",
        resource: jar,
        handle: owner,
      });
    }
  }

  /** Close now; on failure the scope retains the owner for `close()` and the call fails. */
  async #releaseOrRetain(
    owner: Parameters<ArtifactResourceScope["release"]>[0],
  ): Promise<void> {
    const attempt = await this.#resources.release(owner);
    if (attempt.kind === "failed") throw attempt.cause;
  }

  /**
   * Enumerate the archive once, honor the Multi-Release manifest, and resolve
   * the caller's entry/release to exactly one member — refusing an inert
   * versioned selection, an absent release, or an ambiguous duplicate.
   */
  async #selectJarMember(
    reader: ZipArtifactReader,
    entry: string,
    requestedRelease: number | undefined,
    jar: string,
    signal: AbortSignal | undefined,
  ): Promise<
    Result<
      { readonly member: ArtifactEntry; readonly release: number | null },
      AnalysisError
    >
  > {
    let manifestEntry: ArtifactEntry | undefined;
    const byRelease = new Map<number | null, ArtifactEntry[]>();
    for await (const member of reader.entries(signal)) {
      // Encrypted members are kept as candidates: the entry exists but is
      // unreadable, which must be reported as such, not as "not found".
      if (member.kind !== "file") continue;
      if (member.path === "META-INF/MANIFEST.MF") {
        manifestEntry = member;
        continue;
      }
      const candidate = classifyJarEntry(member.path, entry);
      if (candidate === undefined) continue;
      const members = byRelease.get(candidate.release) ?? [];
      members.push(member);
      byRelease.set(candidate.release, members);
    }
    // Without a requested release, a present base entry is selected whatever
    // the manifest says, so an unreadable manifest must not block it.
    const needsManifest =
      requestedRelease !== undefined || !byRelease.has(null);
    const multiRelease =
      needsManifest &&
      manifestEntry !== undefined &&
      isMultiReleaseManifest(
        await this.#readEntryBytes(reader, manifestEntry, signal),
      );
    if (!multiRelease && requestedRelease !== undefined)
      return err(
        this.#inputError(
          "release",
          `${jar} is not a multi-release JAR (no Multi-Release: true manifest attribute); META-INF/versions entries are inert, so only the base entry is selectable.`,
        ),
      );
    // Outside a multi-release JAR, versioned entries never load; drop them.
    const effective = new Map<number | null, ArtifactEntry[]>();
    if (multiRelease) for (const [r, m] of byRelease) effective.set(r, m);
    else {
      const base = byRelease.get(null);
      if (base !== undefined) effective.set(null, base);
    }
    const candidates = [...effective.entries()].map(([release, members]) => ({
      release,
      path: members[0]!.path,
    }));
    const selection = resolveJarSelection(candidates, requestedRelease);
    if (!selection.ok) return err(this.#selectionError(selection, jar, entry));
    const selectedMembers = effective.get(selection.release) ?? [];
    if (selectedMembers.length !== 1)
      return err(
        this.#inputError(
          "entry",
          `${jar} holds ${String(selectedMembers.length)} members at the selected entry and release; the identity is ambiguous, so no member is chosen.`,
        ),
      );
    const member = selectedMembers[0]!;
    if (member.encrypted)
      return err(
        new AnalysisUnsupportedTargetError(
          OPERATION,
          jar,
          `The selected entry ${entry} is encrypted and cannot be read without a key; its debug metadata is unavailable, not absent.`,
        ),
      );
    return ok({ member, release: selection.release });
  }

  #inputError(field: "entry" | "release", message: string): AnalysisInputError {
    return new AnalysisInputError(OPERATION, undefined, [
      { path: [field], reason: "invalid_value", message },
    ]);
  }

  /** Buffer one archive member, bounded by the class-file input budget. */
  async #readEntryBytes(
    reader: ZipArtifactReader,
    member: ArtifactEntry,
    signal: AbortSignal | undefined,
  ): Promise<Uint8Array> {
    const stream = await reader.open(member, signal);
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of stream) {
      if (signal?.aborted) {
        stream.destroy();
        throw new ArtifactReaderFailure("cancelled", "JAR read cancelled");
      }
      if (!Buffer.isBuffer(chunk)) {
        stream.destroy();
        throw new ArtifactReaderFailure(
          "format",
          "JAR entry did not yield bytes",
        );
      }
      size += chunk.length;
      if (size > JVM_LIMITS.inputBytes) {
        stream.destroy();
        throw new ArtifactReaderFailure(
          "limit",
          `Selected class entry exceeds ${String(JVM_LIMITS.inputBytes)} bytes`,
        );
      }
      chunks.push(chunk);
    }
    return Buffer.concat(chunks, size);
  }

  /**
   * Refuse before the (potentially ~50x) expansion into entry objects: a crafted
   * class near the input budget can declare millions of fixed-stride table
   * entries. The pre-count reads only table headers and allocates nothing.
   */
  /**
   * Refuse before building the report: too many projected objects, too many
   * debug-relevant attributes, or a projected serialization (counting every
   * repeated constant-pool string) past the inline output budget.
   */
  #rejectIfTooManyEntries(
    classFile: Parameters<typeof projectDebugOutput>[0],
    path: string,
    echoed: readonly string[],
  ): AnalysisResourceConstraintError | undefined {
    const projection = projectDebugOutput(
      classFile,
      JVM_LIMITS.maxDebugEntries,
      {
        entries: JVM_LIMITS.maxDebugEntries,
        encodedBytes: JVM_LIMITS.outputBytes,
      },
    );
    if (projection.attributeBudgetExceeded)
      return new AnalysisResourceConstraintError(
        OPERATION,
        "capacity",
        `${path} declares more than ${String(JVM_LIMITS.maxDebugEntries)} debug-relevant attributes; refused before materialising them.`,
        { max_retained_attributes: JVM_LIMITS.maxDebugEntries },
      );
    if (projection.entries > JVM_LIMITS.maxDebugEntries)
      return new AnalysisResourceConstraintError(
        OPERATION,
        "memory",
        `${path} declares ${String(projection.entries)} debug-table entries, over the ${String(JVM_LIMITS.maxDebugEntries)} limit; refused before allocation.`,
        { maximum_debug_entries: JVM_LIMITS.maxDebugEntries },
      );
    // Caller-selected strings (path, entry name) are echoed verbatim too.
    const encodedBytes = echoed.reduce(
      (total, value) => total + Buffer.byteLength(JSON.stringify(value)),
      projection.encodedBytes,
    );
    if (encodedBytes > JVM_LIMITS.outputBytes)
      return new AnalysisResourceConstraintError(
        OPERATION,
        "capacity",
        `${path} would project to about ${String(encodedBytes)} bytes of debug metadata, over the ${String(JVM_LIMITS.outputBytes)}-byte output budget; refused before building it.`,
        { maximum_output_bytes: JVM_LIMITS.outputBytes },
      );
    return undefined;
  }

  #rejectIfOversized(
    result: JavaDebugMetadataResult,
    path: string,
  ): AnalysisResourceConstraintError | undefined {
    // Input bounds do not bound the projected result; a crafted class can
    // declare millions of table entries. Refuse past the inline output budget
    // instead of emitting oversized Evidence (mirrors the Go/Rust readers).
    if (
      Buffer.byteLength(JSON.stringify(result), "utf8") <=
      JVM_LIMITS.outputBytes
    )
      return undefined;
    return new AnalysisResourceConstraintError(
      OPERATION,
      "transport",
      `Decoded debug metadata for ${path} exceeds the inline output budget; no partial success is returned.`,
      { maximum_output_bytes: JVM_LIMITS.outputBytes },
    );
  }

  #selectionError(
    selection: {
      readonly reason: "not-found" | "release-absent";
      readonly available: readonly number[];
    },
    jar: string,
    entry: string,
  ): AnalysisInputError {
    const message =
      selection.reason === "not-found"
        ? `No class entry ${entry} exists in ${jar}.`
        : `Entry ${entry} is not available for the requested release in ${jar}; available multi-release versions: ${selection.available.length === 0 ? "none (base only)" : selection.available.join(", ")}.`;
    return new AnalysisInputError(OPERATION, undefined, [
      {
        path: [selection.reason === "not-found" ? "entry" : "release"],
        reason: "invalid_value",
        message,
      },
    ]);
  }
}
