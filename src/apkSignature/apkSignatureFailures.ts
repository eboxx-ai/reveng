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
import type { ApkSchemeError } from "../domain/apkSignature/apkSignatureSchemes.js";
import type { ApkSigningBlockError } from "../domain/apkSignature/apkSigningBlock.js";
import type { ApkCentralDirectoryError } from "../domain/apkSignature/apkV1Signature.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import {
  APK_SIGNATURE_LIMITS,
  APK_SIGNATURE_PROVIDER_IDENTITY,
} from "./ApkSignatureRelease.js";

const OPERATION = "inspect_apk_signature";

const inputError = (message: string): AnalysisInputError =>
  new AnalysisInputError(OPERATION, undefined, [
    { path: ["path"], reason: "invalid_value", message },
  ]);

/** Map a tagged signing-block framing failure to the shared analysis error algebra. */
export const mapApkBlockError = (
  error: ApkSigningBlockError,
  path: string,
): AnalysisError => {
  switch (error.kind) {
    case "not-a-zip":
      return new AnalysisUnsupportedTargetError(
        OPERATION,
        path,
        `The selected file is not a ZIP/APK (${error.detail}).`,
        { remediationAction: "Select a local .apk/.zip/.aab archive." },
      );
    case "zip64-unsupported":
      return new AnalysisUnsupportedTargetError(
        OPERATION,
        path,
        `This archive uses a Zip64 structure this reader does not decode (${error.detail}).`,
      );
    case "malformed-zip":
      return inputError(
        `Damaged ZIP/APK at byte ${String(error.offset)}: ${error.detail}.`,
      );
    case "malformed-block":
      return inputError(
        `Malformed APK Signing Block at byte ${String(error.offset)}: ${error.detail}.`,
      );
    case "budget-exceeded":
      return new AnalysisResourceConstraintError(
        OPERATION,
        "capacity",
        `APK Signing Block holds more ${error.resource} than the ${String(error.limit)} limit.`,
        { max_signing_block_pairs: error.limit },
      );
  }
};

/** Map a tagged signer/lineage decoding failure, naming the scheme it came from. */
export const mapApkSchemeError = (
  error: ApkSchemeError,
  scheme: string,
): AnalysisError =>
  error.kind === "malformed-signer"
    ? inputError(
        `Malformed APK Signature Scheme ${scheme} block: ${error.detail}.`,
      )
    : new AnalysisResourceConstraintError(
        OPERATION,
        "capacity",
        `APK Signature Scheme ${scheme} holds more ${error.resource} than the ${String(error.limit)} limit.`,
        { [`max_${error.resource.replace(/-/g, "_")}`]: error.limit },
      );

/** A central directory that cannot be walked leaves v1 presence unknown: refuse. */
export const mapCentralDirectoryError = (
  error: ApkCentralDirectoryError,
): AnalysisError =>
  error.kind === "budget-exceeded"
    ? new AnalysisResourceConstraintError(
        OPERATION,
        "capacity",
        `The central directory holds more than ${String(error.limit)} top-level META-INF entries.`,
        { max_meta_inf_entries: error.limit },
      )
    : inputError(
        `Malformed ZIP central directory at byte ${String(error.offset)}: ${error.detail}.`,
      );

/** The decoded result would exceed the inline output budget. */
export const apkOutputBudgetError = (projectedBytes: number): AnalysisError =>
  new AnalysisResourceConstraintError(
    OPERATION,
    "capacity",
    `The decoded signing report (${String(projectedBytes)} bytes) exceeds the ${String(APK_SIGNATURE_LIMITS.outputBytes)}-byte output budget.`,
    { max_output_bytes: APK_SIGNATURE_LIMITS.outputBytes },
  );

/**
 * Map a read or analysis failure, keeping a failed descriptor close as a
 * cleanup fact bound to the error (its lease retried by the provider's
 * close()), as the other stable-read providers do.
 */
export const apkSignatureFailure = (
  cause: unknown,
  path: string,
  signal?: AbortSignal,
): AnalysisError => {
  const primary =
    cause instanceof ArtifactFileCleanupFailure &&
    cause.fileCleanupFailure.outcome.kind === "failed"
      ? primaryFailure(cause.fileCleanupFailure.outcome.cause, path)
      : cause instanceof ArtifactFileCleanupFailure && signal?.aborted
        ? new AnalysisCancelledError(OPERATION, { cause: signal.reason })
        : primaryFailure(cause, path);
  if (!(cause instanceof ArtifactReaderFailure) || cause.cleanup === undefined)
    return primary;
  const cleanup = new ProviderCleanupError(
    APK_SIGNATURE_PROVIDER_IDENTITY.id,
    cause.cleanup.resources,
    { reason: cause.cleanup.reason },
    { cause, operation: OPERATION },
  );
  const error = analysisErrorWithCleanupFailure(primary, cleanup, OPERATION);
  bindArtifactFileCleanup(cause, error);
  return error;
};

/** Distinguish cancellation, access, integrity and limits for the primary failure. */
const primaryFailure = (cause: unknown, path: string): AnalysisError => {
  if (cause instanceof AnalysisError) return cause;
  const reason = cause instanceof Error ? cause.message : String(cause);
  if (
    (cause instanceof ArtifactReaderFailure && cause.reason === "cancelled") ||
    (cause instanceof Error && cause.name === "AbortError")
  )
    return new AnalysisCancelledError(OPERATION, { cause });
  if (cause instanceof ArtifactReaderFailure && cause.reason === "limit")
    return new AnalysisResourceConstraintError(
      OPERATION,
      "file-size",
      reason,
      { max_input_bytes: APK_SIGNATURE_LIMITS.inputBytes },
      {
        cause,
        remediationAction:
          "The size budget is fixed; select a smaller archive.",
      },
    );
  if (cause instanceof ArtifactReaderFailure && cause.reason === "integrity")
    return new AnalysisArtifactChangedError(OPERATION, path, reason, { cause });
  if (
    cause instanceof Error &&
    "code" in cause &&
    (cause.code === "EACCES" || cause.code === "EPERM")
  )
    return new AnalysisAccessDeniedError(OPERATION, path, cause.code, {
      cause,
    });
  if (
    cause instanceof Error &&
    "code" in cause &&
    (cause.code === "ENOENT" ||
      cause.code === "ENOTDIR" ||
      cause.code === "ELOOP")
  )
    return new AnalysisInputError(OPERATION, { cause }, [
      {
        path: ["path"],
        reason: "invalid_value",
        message: `No regular file can be read at the selected path (${String(cause.code)}): ${path}.`,
      },
    ]);
  // A typed reader failure (format, path, io, unavailable) describes the
  // selected artifact, so it stays a caller-facing input error.
  if (cause instanceof ArtifactReaderFailure)
    return new AnalysisInputError(OPERATION, { cause }, [
      { path: ["path"], reason: "invalid_value", message: reason },
    ]);
  // Anything else is an adapter defect, not a caller input problem.
  return new ProviderAdapterError(
    APK_SIGNATURE_PROVIDER_IDENTITY.id,
    OPERATION,
    {
      cause,
      diagnostics: { path, reason },
    },
  );
};
