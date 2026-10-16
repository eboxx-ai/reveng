import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import {
  ArtifactFileCleanupFailure,
  bindArtifactFileCleanup,
} from "../artifacts/ArtifactFileOperation.js";
import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
  AnalysisUnsupportedTargetError,
} from "../domain/analysisErrorCore.js";
import type { JavaClassFileParseError } from "../domain/jvm/javaClassFile.js";
import { JVM_LIMITS, JVM_PROVIDER_IDENTITY } from "./JvmClassFileRelease.js";

const OPERATION = "inspect_jvm_debug_metadata";

/** Map a tagged class-file parse failure to the shared analysis error algebra. */
export const mapParseError = (
  error: JavaClassFileParseError,
  path: string,
): AnalysisError => {
  switch (error.kind) {
    case "bad-magic":
      return new AnalysisUnsupportedTargetError(
        OPERATION,
        path,
        "The selected file does not begin with the 0xCAFEBABE class-file magic.",
        {
          remediationAction:
            "Select a single compiled .class file; archives and other formats are not class files.",
        },
      );
    case "truncated":
      return new AnalysisInputError(OPERATION, undefined, [
        {
          path: ["path"],
          reason: "invalid_format",
          message: `Class file ended before a structure completed at byte ${String(error.offset)}.`,
        },
      ]);
    case "unsupported-constant-tag":
      return new AnalysisInputError(OPERATION, undefined, [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `Unsupported constant-pool tag ${String(error.tag)} at byte ${String(error.offset)}.`,
        },
      ]);
    case "invalid-utf8":
      return new AnalysisInputError(OPERATION, undefined, [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `Malformed modified-UTF8 constant at byte ${String(error.offset)}.`,
        },
      ]);
    case "budget-exceeded":
      return new AnalysisInputError(OPERATION, undefined, [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `Declared ${error.resource} count (${String(error.declared)}) exceeds the remaining ${String(error.remaining)} bytes at byte ${String(error.offset)}.`,
        },
      ]);
    case "retained-attribute-budget":
      return new AnalysisResourceConstraintError(
        OPERATION,
        "capacity",
        `The class declares more than ${String(error.limit)} debug-relevant attributes (at byte ${String(error.offset)}); refused before materialising them.`,
        { max_retained_attributes: error.limit },
      );
  }
};

/**
 * Map a read or analysis failure. A failed descriptor close keeps the read's
 * primary failure (or cancellation) and binds its cleanup lease to the error,
 * so the provider's close() retries the retained handle.
 */
export const jvmClassFileFailure = (
  cause: unknown,
  path: string,
  signal?: AbortSignal,
): AnalysisError => {
  const error =
    cause instanceof ArtifactFileCleanupFailure &&
    cause.fileCleanupFailure.outcome.kind === "failed"
      ? withCleanupFacts(
          primaryFailure(cause.fileCleanupFailure.outcome.cause, path),
          cause,
        )
      : cause instanceof ArtifactFileCleanupFailure && signal?.aborted
        ? withCleanupFacts(
            new AnalysisCancelledError(OPERATION, { cause: signal.reason }),
            cause,
          )
        : primaryFailure(cause, path);
  bindArtifactFileCleanup(cause, error);
  return error;
};

/** Attach a failed close as a cleanup fact to a primary failure. */
const withCleanupFacts = (
  primary: AnalysisError,
  cause: ArtifactReaderFailure,
): AnalysisError =>
  cause.cleanup === undefined
    ? primary
    : analysisErrorWithCleanupFailure(
        primary,
        new ProviderCleanupError(
          JVM_PROVIDER_IDENTITY.id,
          cause.cleanup.resources,
          { reason: cause.cleanup.reason },
          { cause, operation: OPERATION },
        ),
        OPERATION,
      );

/** Distinguish cancellation, access, integrity and limits for the primary failure. */
const primaryFailure = (cause: unknown, path: string): AnalysisError => {
  if (cause instanceof AnalysisError) return cause;
  const cleanup =
    cause instanceof ArtifactReaderFailure && cause.cleanup !== undefined
      ? { cleanup: cause.cleanup }
      : {};
  const reason = cause instanceof Error ? cause.message : String(cause);
  if (
    (cause instanceof ArtifactReaderFailure && cause.reason === "cancelled") ||
    (cause instanceof Error && cause.name === "AbortError")
  )
    return new AnalysisCancelledError(OPERATION, { cause, ...cleanup });
  if (cause instanceof ArtifactReaderFailure && cause.reason === "limit")
    return new AnalysisResourceConstraintError(
      OPERATION,
      "file-size",
      reason,
      { max_input_bytes: JVM_LIMITS.inputBytes },
      {
        cause,
        ...cleanup,
        remediationAction:
          "The class-file size budget is fixed; select a smaller artifact.",
      },
    );
  if (cause instanceof ArtifactReaderFailure && cause.reason === "integrity")
    return new AnalysisArtifactChangedError(OPERATION, path, reason, {
      cause,
      ...cleanup,
    });
  if (
    cause instanceof Error &&
    "code" in cause &&
    (cause.code === "EACCES" || cause.code === "EPERM")
  )
    return new AnalysisAccessDeniedError(OPERATION, path, cause.code, {
      cause,
      ...cleanup,
    });
  // The only work after input validation is reading the selected file and a
  // total in-process parse, so a remaining thrown error is an artifact-read
  // problem (missing path, not a regular file, I/O), not a producer fault.
  return new AnalysisInputError(OPERATION, { cause, ...cleanup }, [
    { path: ["path"], reason: "invalid_value", message: reason },
  ]);
};
