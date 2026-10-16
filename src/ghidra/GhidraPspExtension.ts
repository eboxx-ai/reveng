import { createHash } from "node:crypto";
import { lstat, opendir, realpath } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { z } from "zod";
import { sameRegularFileState } from "../filesystem/RegularFile.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import {
  assertArtifactReadActive,
  artifactFileCancellationCause,
  artifactFilePrimaryFailure,
  bindArtifactFileCleanup,
  withArtifactRegularFile,
} from "../artifacts/ArtifactFileOperation.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
} from "../domain/analysisErrorCore.js";
import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { err, ok, type Result } from "../domain/result.js";
import type { GhidraInstallationInspection } from "./GhidraInstallation.js";
import { parseGhidraJavaProperties } from "./GhidraJavaProperties.js";

/** Installed processor code and data, distinct from REA's analysis-extension ABI. */
export const ghidraPspExtensionSchema = z.strictObject({
  id: z.literal("ghidra-allegrex"),
  root: z.string().refine(isAbsolute),
  ghidra_version: z.string().min(1),
  sha256: z.string().regex(/^[a-f0-9]{64}$/u),
});
export type GhidraPspExtension = z.infer<typeof ghidraPspExtensionSchema>;

// Resource bounds for scanning a caller-installed extension, not target limits.
const MAX_ENTRIES = 1024;
const MAX_BYTES = 64 * 1024 * 1024;
const MAX_DEPTH = 16;
const REQUIRED = [
  "Module.manifest",
  "extension.properties",
  "data/languages/allegrex.ldefs",
  "data/languages/allegrex.sla",
  "data/languages/allegrex.pspec",
  "data/languages/allegrex.cspec",
];

/** Read-only fingerprint of all installed files; no home scanning or installation. */
export const inspectGhidraPspExtension = async (
  root: string,
  ghidraVersion: string,
  signal?: AbortSignal,
): Promise<GhidraPspExtension> => {
  assertArtifactReadActive(signal);
  if (!isAbsolute(root) || (await realpath(root)) !== root)
    throw new Error(
      "The installed Allegrex directory must be a canonical non-symlink path.",
    );
  const files: string[] = [];
  let entries = 1; // The root itself consumes one inventory entry.
  const visit = async (relative: string, depth: number): Promise<void> => {
    assertArtifactReadActive(signal);
    if (depth > MAX_DEPTH)
      throw new Error(
        "Allegrex extension directory nesting exceeds the inspection limit.",
      );
    const path = join(root, relative);
    const metadata = await lstat(path);
    if (metadata.isDirectory()) {
      const children: string[] = [];
      for await (const child of await opendir(path)) {
        assertArtifactReadActive(signal);
        if (++entries > MAX_ENTRIES)
          throw new Error(
            "Allegrex extension inventory exceeds the inspection limit.",
          );
        children.push(child.name);
      }
      children.sort();
      for (const child of children)
        await visit(
          relative === "" ? child : `${relative}/${child}`,
          depth + 1,
        );
    } else if (metadata.isFile()) {
      files.push(relative);
    } else
      throw new Error(
        `Allegrex extension entries must be regular files or directories: ${relative}`,
      );
  };
  await visit("", 0);
  for (const required of REQUIRED)
    if (!files.includes(required))
      throw new Error(`Missing installed Allegrex component: ${required}`);
  if (!files.some((path) => path.startsWith("lib/") && path.endsWith(".jar")))
    throw new Error("The installed Allegrex extension has no loader JAR.");

  // One owner for every admitted descriptor: a rejected close retains its exact
  // owner for a bounded retry instead of replacing the physical read outcome.
  const resources = new ArtifactResourceScope();
  const hash = createHash("sha256");
  let bytesRead = 0;
  let properties = Buffer.alloc(0);
  let outcome:
    | { readonly kind: "completed"; readonly value: GhidraPspExtension }
    | { readonly kind: "failed"; readonly cause: unknown };
  try {
    for (const relative of files) {
      assertArtifactReadActive(signal);
      const path = join(root, relative);
      await withArtifactRegularFile(path, resources, signal, async (handle) => {
        const before = await handle.stat();
        if (
          !Number.isSafeInteger(before.size) ||
          before.size > MAX_BYTES - bytesRead
        )
          throw new Error(
            "Allegrex extension bytes exceed the inspection limit.",
          );
        if (relative === "extension.properties" && before.size > 65536)
          throw new Error(
            "Allegrex extension properties exceed the inspection limit.",
          );
        hash.update(JSON.stringify([relative, before.size]));
        const buffer = Buffer.alloc(Math.min(65536, before.size + 1));
        let offset = 0;
        const chunks: Buffer[] = [];
        while (offset < before.size) {
          assertArtifactReadActive(signal);
          const read = await handle.read(
            buffer,
            0,
            Math.min(buffer.length, before.size - offset),
            offset,
          );
          if (read.bytesRead === 0)
            throw new Error(`Truncated Allegrex component: ${relative}`);
          const chunk = buffer.subarray(0, read.bytesRead);
          hash.update(chunk);
          if (relative === "extension.properties")
            chunks.push(Buffer.from(chunk));
          offset += read.bytesRead;
        }
        if (
          !sameRegularFileState(before, await handle.stat()) ||
          !sameRegularFileState(before, await lstat(path))
        )
          throw new Error(
            `Allegrex component changed during inspection: ${relative}`,
          );
        bytesRead += before.size;
        if (relative === "extension.properties")
          properties = Buffer.concat(chunks);
      });
    }
    // Ghidra's extension.properties version is the compatible Ghidra version,
    // not the extension release (e.g. v21.4); content identity supplies the latter.
    const parsedProperties = parseGhidraJavaProperties(
      properties.toString("latin1"),
    );
    if (!parsedProperties.ok)
      throw new Error(
        `Invalid Allegrex extension properties: ${parsedProperties.error}`,
      );
    const property = (name: string): string | undefined =>
      parsedProperties.value.get(name);
    if (
      property("name") !== "ghidra-allegrex" ||
      property("version") !== ghidraVersion
    )
      throw new Error(
        `Allegrex extension metadata does not match the selected Ghidra ${ghidraVersion}; install or rebuild a compatible extension.`,
      );
    assertArtifactReadActive(signal);
    outcome = {
      kind: "completed",
      value: {
        id: "ghidra-allegrex",
        root,
        ghidra_version: ghidraVersion,
        sha256: hash.digest("hex"),
      },
    };
  } catch (cause: unknown) {
    outcome = { kind: "failed", cause };
  }
  // Retry every retained descriptor before the owner completes. A still-failing
  // close keeps the physical inspection outcome primary and the exact owner as
  // cleanup, rather than replacing the read/change/format failure.
  try {
    await resources.close();
  } catch (cleanupCause: unknown) {
    const cleanup = ArtifactReaderFailure.cleanupObservation(
      cleanupCause,
      root,
    );
    throw ArtifactReaderFailure.withCleanup(
      outcome.kind === "failed" ? outcome.cause : cleanupCause,
      cleanup,
    );
  }
  if (outcome.kind === "failed") throw outcome.cause;
  return outcome.value;
};

/** Resolve prerequisites before opening or admitting cached PSP analysis. */
export const resolveGhidraPspExtension = async (
  installation: GhidraInstallationInspection,
  signal?: AbortSignal,
): Promise<Result<GhidraPspExtension, AnalysisError>> => {
  try {
    // Cancellation is observed by this producer, so it is reported here rather
    // than substituted for a later physical failure in the catch.
    assertArtifactReadActive(signal);
    if (
      installation.status !== "available" ||
      installation.platform !== "linux" ||
      installation.architecture !== "x64"
    )
      throw new Error(
        "The initial PSP profile requires a supported Linux x64 Ghidra installation.",
      );
    const root = join(
      await realpath(installation.installDir),
      "Ghidra",
      "Extensions",
      "ghidra-allegrex",
    );
    return ok(
      await inspectGhidraPspExtension(
        root,
        installation.providerVersion,
        signal,
      ),
    );
  } catch (cause: unknown) {
    return err(pspExtensionFailure(cause));
  }
};

/** Normalize the producer's outcome instead of substituting a later cancellation. */
const pspExtensionFailure = (cause: unknown): AnalysisError => {
  const primary = artifactFilePrimaryFailure(cause);
  // Cancellation is reported only when a producer observed the caller signal.
  const cancelled =
    primary instanceof ArtifactReaderFailure && primary.reason === "cancelled";
  const reason = `PSP_EXTENSION_UNAVAILABLE: ${cause instanceof Error ? cause.message : String(cause)} Use a compatible caller-installed ghidra-allegrex under GHIDRA_INSTALL_DIR/Ghidra/Extensions; REA does not install it.`;
  const failure = cancelled
    ? new AnalysisCancelledError("resolve_analysis_profile", {
        cause: artifactFileCancellationCause(primary),
      })
    : new AnalysisCapabilityUnavailableError(
        "ghidra",
        "resolve_analysis_profile",
        reason,
        { cause, userMessage: reason },
      );
  // An unconfirmed descriptor close stays owned alongside the primary outcome.
  const cleanup =
    cause instanceof ArtifactReaderFailure ? cause.cleanup : undefined;
  if (cleanup === undefined) return failure;
  const cleanupFailure = new ProviderCleanupError(
    "ghidra",
    cleanup.resources,
    { reason: cleanup.reason },
    { operation: "resolve_analysis_profile", cause },
  );
  bindArtifactFileCleanup(cause, cleanupFailure);
  return analysisErrorWithCleanupFailure(
    failure,
    cleanupFailure,
    "resolve_analysis_profile",
  );
};
