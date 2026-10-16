import { createHash, X509Certificate } from "node:crypto";

import { createAnalysisExecution } from "../application/AnalysisProvider.js";
import type { ExecutionOptions } from "../application/AnalysisProvider.js";
import type {
  ApkSignatureExecution,
  ApkSignaturePort,
} from "../application/apkSignature/ApkSignaturePort.js";
import { readStableArtifact } from "../artifacts/readStableArtifact.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { bindArtifactFileCleanup } from "../artifacts/ArtifactFileOperation.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";
import {
  APK_BLOCK_ID,
  locateApkSigningBlock,
  parseZipTail,
  type ApkSigningBlock,
  type ZipTail,
} from "../domain/apkSignature/apkSigningBlock.js";
import {
  contentDigestAlgorithm,
  decodeRotationLineage,
  decodeSigners,
  PROOF_OF_ROTATION_ATTR_ID,
  type ApkLineageNode,
  type ApkSchemeError,
  type ApkSchemeVersion,
  type ApkSigner,
} from "../domain/apkSignature/apkSignatureSchemes.js";
import {
  APK_SIGNATURE_LIMITATIONS,
  deriveApkPosture,
  type ApkSignatureResult,
} from "../domain/apkSignature/apkSignatureReport.js";
import {
  computeApkContentDigest,
  type HashFactory,
} from "../domain/apkSignature/apkContentDigest.js";
import {
  centralDirectoryMetaInfNames,
  detectV1Signature,
} from "../domain/apkSignature/apkV1Signature.js";
import { err, ok, type Result } from "../domain/result.js";
import { zipPackageFormatForPath } from "../domain/zipPackageFormat.js";
import {
  apkOutputBudgetError,
  apkSignatureFailure,
  mapApkBlockError,
  mapApkSchemeError,
  mapCentralDirectoryError,
} from "./apkSignatureFailures.js";
import {
  APK_SIGNATURE_LIMITS,
  APK_SIGNATURE_PROVIDER_IDENTITY,
} from "./ApkSignatureRelease.js";

const OPERATION = "inspect_apk_signature";

type Certificate =
  ApkSignatureResult["schemes"]["v2"]["signers"][number]["certificate"];
type Signer = ApkSignatureResult["schemes"]["v2"]["signers"][number];
type SignerV3 = ApkSignatureResult["schemes"]["v3"]["signers"][number];

/** SHA-256 over the raw embedded DER — exactly what apksig/apksigner hash. */
const derFingerprint = (der: Uint8Array): string =>
  createHash("sha256").update(der).digest("hex");

/** Each fact is read independently so one unsupported field does not hide the rest. */
const attempt = <T>(read: () => T): T | null => {
  try {
    return read();
  } catch {
    return null;
  }
};

/** Identity is the raw-DER fingerprint; parsed X.509 facts are null when unreadable. */
const certificateFacts = (der: Uint8Array): Certificate => {
  const cert = attempt(() => new X509Certificate(Buffer.from(der)));
  return {
    sha256_fingerprint: derFingerprint(der),
    subject: cert?.subject ?? null,
    issuer: cert?.issuer ?? null,
    serial_number: cert?.serialNumber ?? null,
    not_before: cert ? attempt(() => cert.validFromDate.toISOString()) : null,
    not_after: cert ? attempt(() => cert.validToDate.toISOString()) : null,
    public_key_algorithm: cert
      ? attempt(() => cert.publicKey.asymmetricKeyType ?? null)
      : null,
  };
};

/** Compares a signed digest with the recomputed content digest; null when not computable. */
interface DigestMatcher {
  readonly match: (algorithmId: number, signed: Uint8Array) => boolean | null;
  /** True once a SHA-256/512 digest was requested but the layout prevented recomputing it. */
  readonly layoutPreventedRecompute: () => boolean;
}

const nodeHash: HashFactory = (algorithm) => {
  const hash = createHash(algorithm);
  return {
    update: (data) => {
      hash.update(data);
    },
    digest: () => new Uint8Array(hash.digest()),
  };
};

/** Recompute each content digest at most once per algorithm, lazily. */
const digestMatcher = (
  bytes: Uint8Array,
  tail: ZipTail,
  blockStart: number | null,
): DigestMatcher => {
  const cache = new Map<"sha256" | "sha512", Uint8Array | null>();
  return {
    match: (algorithmId, signed) => {
      const algorithm = contentDigestAlgorithm(algorithmId);
      // verity (fs-verity Merkle) digests and unknown algorithms are not recomputed.
      if (
        blockStart === null ||
        (algorithm !== "sha256" && algorithm !== "sha512")
      )
        return null;
      if (!cache.has(algorithm))
        cache.set(
          algorithm,
          computeApkContentDigest(
            bytes,
            { tail, blockStart, algorithm },
            nodeHash,
          ),
        );
      const computed = cache.get(algorithm) ?? null;
      return computed === null ? null : Buffer.from(computed).equals(signed);
    },
    layoutPreventedRecompute: () =>
      [...cache.values()].some((value) => value === null),
  };
};

/** Proof-of-rotation capability bits (apksig SigningCertificateLineage). */
const capabilities = (
  flags: number,
): SignerV3["rotation"]["lineage"][number]["capabilities"] => ({
  installed_data: (flags & 0x1) !== 0,
  shared_uid: (flags & 0x2) !== 0,
  permission: (flags & 0x4) !== 0,
  rollback: (flags & 0x8) !== 0,
  auth: (flags & 0x10) !== 0,
});

/** A decoded signer plus its decoded (or failed) declared lineage. */
interface DecodedSigner {
  readonly signer: ApkSigner;
  readonly rotation:
    | { readonly present: false }
    | { readonly present: true; readonly nodes: readonly ApkLineageNode[] }
    | { readonly present: true; readonly decodeError: string };
}

interface DecodedScheme {
  readonly present: boolean;
  readonly signers: readonly DecodedSigner[];
}

const lineageOf = (
  signer: ApkSigner,
): Result<DecodedSigner["rotation"], ApkSchemeError> => {
  const attribute = signer.attributes.find(
    (a) => a.id === PROOF_OF_ROTATION_ATTR_ID,
  );
  if (attribute === undefined) return ok({ present: false });
  const nodes = decodeRotationLineage(attribute.value);
  if (nodes.ok) return ok({ present: true, nodes: nodes.value });
  // A malformed lineage is reported, not dropped; an over-cap lineage is refused.
  return nodes.error.kind === "malformed-signer"
    ? ok({ present: true, decodeError: nodes.error.detail })
    : nodes;
};

/**
 * Estimated serialized size of one certificate's facts. RFC 2253-escaped DNs
 * can reach ~2.6x the DER once JSON-escaped, hence 3x; this is an admission
 * estimate — the exact serialized re-check below is authoritative.
 */
const certificateBytes = (der: Uint8Array | undefined): number =>
  256 + 3 * (der?.length ?? 0);

/** Project the result size from decoded counts before materialising any of it. */
const projectedOutputBytes = (schemes: readonly DecodedScheme[]): number => {
  let total = 4096;
  for (const scheme of schemes)
    for (const { signer, rotation } of scheme.signers) {
      total += 128 + certificateBytes(signer.certificates[0]);
      total += 64 * signer.digests.length;
      if (rotation.present && "nodes" in rotation)
        for (const node of rotation.nodes)
          total += 192 + certificateBytes(node.certificate);
    }
  return total;
};

const digestsOf = (
  signer: ApkSigner,
  matcher: DigestMatcher,
): Signer["digests"] =>
  signer.digests.map((d) => ({
    algorithm: contentDigestAlgorithm(d.algorithmId) ?? "unknown",
    matches_apk: matcher.match(d.algorithmId, d.digest),
  }));

const baseSigner = (signer: ApkSigner, matcher: DigestMatcher): Signer => ({
  certificate: signer.certificates[0]
    ? certificateFacts(signer.certificates[0])
    : null,
  digests: digestsOf(signer, matcher),
  min_sdk: signer.minSdk,
  max_sdk: signer.maxSdk,
});

const rotationFacts = (
  rotation: DecodedSigner["rotation"],
): SignerV3["rotation"] => {
  if (!rotation.present)
    return { present: false, lineage: [], decode_error: null };
  if ("decodeError" in rotation)
    return { present: true, lineage: [], decode_error: rotation.decodeError };
  return {
    present: true,
    lineage: rotation.nodes.map((node) => ({
      certificate: certificateFacts(node.certificate),
      flags: node.flags,
      capabilities: capabilities(node.flags),
    })),
    decode_error: null,
  };
};

const v3Signer = (
  decoded: DecodedSigner,
  matcher: DigestMatcher,
): SignerV3 => ({
  ...baseSigner(decoded.signer, matcher),
  rotation: rotationFacts(decoded.rotation),
});

/** All recomputed digests agree → true; any mismatch → false; none computed → null. */
const selfConsistency = (
  signers: readonly { readonly digests: Signer["digests"] }[],
): boolean | null => {
  const results = signers
    .flatMap((s) => s.digests.map((d) => d.matches_apk))
    .filter((m): m is boolean => m !== null);
  if (results.length === 0) return null;
  return results.every(Boolean);
};

/** Signer fingerprints; null marks a signer whose certificate is absent. */
const signerFingerprintsOf = (
  signers: readonly { readonly certificate: Certificate }[],
): (string | null)[] =>
  signers.map((s) => s.certificate?.sha256_fingerprint ?? null);

const lineageFingerprintsOf = (
  nodes: readonly { readonly certificate: Certificate }[],
): string[] =>
  nodes.flatMap((n) =>
    n.certificate === null ? [] : [n.certificate.sha256_fingerprint],
  );

const LAYOUT_LIMITATION =
  "The content digest was not recomputed because the central directory is not immediately followed by the end-of-central-directory record (declared size mismatch or an intervening Zip64 record); matches_apk is null for those digests.";

/** Read exactly the selected APK bytes and report its signature schemes. */
export class ApkSignatureProvider implements ApkSignaturePort {
  /** Owns the selected file's descriptor, retaining it when closing fails. */
  readonly #resources = new ArtifactResourceScope();

  async close(): Promise<void> {
    try {
      await this.#resources.close();
    } catch (cause: unknown) {
      if (
        !(cause instanceof ArtifactReaderFailure) ||
        cause.cleanup === undefined
      )
        throw cause;
      const error = new ProviderCleanupError(
        APK_SIGNATURE_PROVIDER_IDENTITY.id,
        cause.cleanup.resources,
        { reason: cause.cleanup.reason },
        { cause, operation: OPERATION },
      );
      bindArtifactFileCleanup(cause, error);
      throw error;
    }
  }

  async inspect(
    input: { readonly path: string },
    options?: ExecutionOptions,
  ): Promise<Result<ApkSignatureExecution, AnalysisError>> {
    try {
      if (options?.signal?.aborted)
        return err(new AnalysisCancelledError(OPERATION));
      const selected = await this.#resources.run(() =>
        readStableArtifact(
          input.path,
          APK_SIGNATURE_LIMITS.inputBytes,
          options?.signal,
          undefined,
          this.#resources,
        ),
      );
      if (options?.signal?.aborted)
        return err(new AnalysisCancelledError(OPERATION));
      return this.#analyze(selected.bytes, {
        path: input.path,
        sha256: selected.sha256,
        bytes: selected.bytes.length,
      });
    } catch (cause: unknown) {
      return err(apkSignatureFailure(cause, input.path, options?.signal));
    }
  }

  #analyze(
    bytes: Uint8Array,
    artifact: { path: string; sha256: string; bytes: number },
  ): Result<ApkSignatureExecution, AnalysisError> {
    const tail = parseZipTail(bytes);
    if (!tail.ok) return err(mapApkBlockError(tail.error, artifact.path));
    const block = locateApkSigningBlock(bytes, tail.value);
    if (!block.ok) return err(mapApkBlockError(block.error, artifact.path));

    const names = centralDirectoryMetaInfNames(
      bytes,
      tail.value.centralDirectoryOffset,
      tail.value.centralDirectorySize,
      tail.value.totalEntries,
    );
    if (!names.ok) return err(mapCentralDirectoryError(names.error));
    const v1 = detectV1Signature(names.value);

    const v2 = decodeScheme(block.value, APK_BLOCK_ID.signatureV2, "v2");
    if (!v2.ok) return err(v2.error);
    const v3 = decodeScheme(block.value, APK_BLOCK_ID.signatureV3, "v3");
    if (!v3.ok) return err(v3.error);
    const v31 = decodeScheme(block.value, APK_BLOCK_ID.signatureV31, "v3.1");
    if (!v31.ok) return err(v31.error);

    // Account for representation expansion before allocating the report.
    const projected = projectedOutputBytes([v2.value, v3.value, v31.value]);
    if (projected > APK_SIGNATURE_LIMITS.outputBytes)
      return err(apkOutputBudgetError(projected));

    const matcher = digestMatcher(
      bytes,
      tail.value,
      block.value?.blockStart ?? null,
    );
    const v2signers = v2.value.signers.map((s) =>
      baseSigner(s.signer, matcher),
    );
    const v3signers = v3.value.signers.map((s) => v3Signer(s, matcher));
    const v31signers = v31.value.signers.map((s) => v3Signer(s, matcher));

    const sourceStampPresent =
      block.value !== null &&
      block.value.pairs.some(
        (p) =>
          p.id === APK_BLOCK_ID.sourceStampV1 ||
          p.id === APK_BLOCK_ID.sourceStampV2,
      );
    const rotationPresent = [...v3signers, ...v31signers].some(
      (s) => s.rotation.present,
    );
    const lineageFingerprints = [...v3signers, ...v31signers].flatMap(
      (signer) => lineageFingerprintsOf(signer.rotation.lineage),
    );

    const result: ApkSignatureResult = {
      artifact,
      schemes: {
        v1: {
          present: v1.present,
          has_manifest: v1.hasManifest,
          signature_files: [...v1.signatureFiles],
          block_files: [...v1.blockFiles],
        },
        v2: { present: v2.value.present, signers: v2signers },
        v3: { present: v3.value.present, signers: v3signers },
        "v3.1": { present: v31.value.present, signers: v31signers },
      },
      source_stamp: { present: sourceStampPresent, certificate: null },
      posture: deriveApkPosture({
        v1Present: v1.present,
        v2Present: v2.value.present,
        v3Present: v3.value.present,
        v31Present: v31.value.present,
        sourceStampPresent,
        rotationPresent,
        schemeSignerFingerprints: [v2signers, v3signers, v31signers].map(
          signerFingerprintsOf,
        ),
        lineageFingerprints,
        selfConsistent: selfConsistency([
          ...v2signers,
          ...v3signers,
          ...v31signers,
        ]),
      }),
      runtime_execution: "not-performed",
    };

    const serialized = Buffer.byteLength(JSON.stringify(result));
    if (serialized > APK_SIGNATURE_LIMITS.outputBytes)
      return err(apkOutputBudgetError(serialized));

    const format =
      (zipPackageFormatForPath(artifact.path) ?? "zip") === "apk"
        ? "apk"
        : "zip";
    return ok(
      createAnalysisExecution(result, APK_SIGNATURE_PROVIDER_IDENTITY, {
        subject: { path: artifact.path, format, sha256: artifact.sha256 },
        locations: [{ kind: "artifact-path", path: artifact.path }],
        limitations: matcher.layoutPreventedRecompute()
          ? [...APK_SIGNATURE_LIMITATIONS, LAYOUT_LIMITATION]
          : [...APK_SIGNATURE_LIMITATIONS],
      }) as ApkSignatureExecution,
    );
  }
}

/** Decode one scheme's signers and their declared lineages, mapping failures by scheme. */
const decodeScheme = (
  block: ApkSigningBlock | null,
  id: number,
  version: ApkSchemeVersion,
): Result<DecodedScheme, AnalysisError> => {
  const pair = block?.pairs.find((p) => p.id === id);
  if (pair === undefined) return ok({ present: false, signers: [] });
  const signers = decodeSigners(pair.value, version);
  if (!signers.ok) return err(mapApkSchemeError(signers.error, version));
  const decoded: DecodedSigner[] = [];
  for (const signer of signers.value) {
    const rotation =
      version === "v2" ? ok({ present: false } as const) : lineageOf(signer);
    if (!rotation.ok) return err(mapApkSchemeError(rotation.error, version));
    decoded.push({ signer, rotation: rotation.value });
  }
  return ok({ present: true, signers: decoded });
};
