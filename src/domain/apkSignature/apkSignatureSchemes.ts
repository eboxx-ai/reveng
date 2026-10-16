/**
 * Decode the signer structures inside an APK Signature Scheme v2/v3/v3.1 block
 * value. Each scheme value is a little-endian, uint32-length-prefixed sequence
 * of signers; a signer carries length-prefixed signed-data (digests, X.509
 * certificate DER, and — for v3/v3.1 — min/max SDK and additional attributes
 * including the proof-of-rotation lineage).
 *
 * This frames the structure and exposes digests (by signature-algorithm id),
 * certificate DER, SDK bounds, and additional attributes. Certificate facts and
 * digest recomputation are layered on top. Dependency-free and bounded: a short
 * or inconsistent length is a `malformed-signer` error, and a count past a
 * format-justified cap is a distinct `budget-exceeded` error, never conflated.
 */
import { type Result, err, ok } from "../result.js";

export type ApkSchemeVersion = "v2" | "v3" | "v3.1";

export type ApkSchemeError =
  | {
      readonly kind: "malformed-signer";
      readonly detail: string;
    }
  | {
      readonly kind: "budget-exceeded";
      readonly resource: string;
      readonly limit: number;
    };

export interface ApkSignerDigest {
  /** APK signature-algorithm id (e.g. 0x0103 = RSA-PKCS1 SHA-256). */
  readonly algorithmId: number;
  readonly digest: Uint8Array;
}

export interface ApkSignerAttribute {
  readonly id: number;
  readonly value: Uint8Array;
}

export interface ApkSigner {
  /** X.509 certificate DER blobs; the first is the signing certificate. */
  readonly certificates: readonly Uint8Array[];
  readonly digests: readonly ApkSignerDigest[];
  readonly minSdk: number | null;
  readonly maxSdk: number | null;
  readonly attributes: readonly ApkSignerAttribute[];
}

/** Additional-attribute id carrying the v3 proof-of-rotation lineage. */
export const PROOF_OF_ROTATION_ATTR_ID = 0x3ba06f8c;

/** Generic cap on digests/certificates/attributes in one signer. */
const MAX_ELEMENTS = 4096;
/**
 * Signers per scheme. Android signs with one or a handful; v3 adds at most one
 * per SDK range. A larger count only multiplies output, so it is refused.
 */
export const MAX_SIGNERS = 32;
/**
 * Lineage nodes. Each key rotation appends one node, so a real lineage is a
 * short chain; a larger declared chain is refused rather than materialised.
 */
export const MAX_LINEAGE_NODES = 32;
/** The only proof-of-rotation lineage encoding version apksig accepts. */
const LINEAGE_VERSION = 1;

/** Sequential little-endian reader over a byte range; every read is bounds-checked. */
class LeReader {
  offset = 0;
  private readonly dv: DataView;
  constructor(private readonly bytes: Uint8Array) {
    this.dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }
  get remaining(): number {
    return this.bytes.length - this.offset;
  }
  u32(): number | null {
    if (this.remaining < 4) return null;
    const v = this.dv.getUint32(this.offset, true);
    this.offset += 4;
    return v;
  }
  /** A uint32-length-prefixed chunk; returns a view over its bytes, or null if oob. */
  lenChunk(): Uint8Array | null {
    const length = this.u32();
    if (length === null || length > this.remaining) return null;
    const start = this.offset;
    this.offset += length;
    return this.bytes.subarray(start, start + length);
  }
}

const malformed = (detail: string): Result<never, ApkSchemeError> =>
  err({ kind: "malformed-signer", detail });

/** Split a length-prefixed sequence into its length-prefixed elements. */
const elements = (
  seq: Uint8Array | null,
  what: string,
  limit = MAX_ELEMENTS,
): Result<Uint8Array[], ApkSchemeError> => {
  if (seq === null) return malformed(`${what} sequence missing or truncated`);
  const reader = new LeReader(seq);
  const out: Uint8Array[] = [];
  while (reader.remaining > 0) {
    if (out.length >= limit)
      return err({ kind: "budget-exceeded", resource: what, limit });
    const el = reader.lenChunk();
    if (el === null) return malformed(`${what} element truncated`);
    out.push(el);
  }
  return ok(out);
};

const decodeDigests = (
  seq: Uint8Array | null,
): Result<ApkSignerDigest[], ApkSchemeError> => {
  const items = elements(seq, "digests");
  if (!items.ok) return items;
  const digests: ApkSignerDigest[] = [];
  for (const item of items.value) {
    const reader = new LeReader(item);
    const algorithmId = reader.u32();
    const digest = reader.lenChunk();
    if (algorithmId === null || digest === null)
      return malformed("digest entry truncated");
    digests.push({ algorithmId, digest });
  }
  return ok(digests);
};

const decodeAttributes = (
  seq: Uint8Array | null,
): Result<ApkSignerAttribute[], ApkSchemeError> => {
  const items = elements(seq, "attributes");
  if (!items.ok) return items;
  const attributes: ApkSignerAttribute[] = [];
  for (const item of items.value) {
    const id = new LeReader(item).u32();
    if (id === null) return malformed("attribute id truncated");
    attributes.push({ id, value: item.subarray(4) });
  }
  return ok(attributes);
};

/** Decode one signer's signed-data chunk (v3/v3.1 carry min/max SDK before attributes). */
const decodeSignedData = (
  signedData: Uint8Array,
  version: ApkSchemeVersion,
): Result<ApkSigner, ApkSchemeError> => {
  const reader = new LeReader(signedData);
  const digests = decodeDigests(reader.lenChunk());
  if (!digests.ok) return digests;
  const certificates = elements(reader.lenChunk(), "certificates");
  if (!certificates.ok) return certificates;
  let minSdk: number | null = null;
  let maxSdk: number | null = null;
  if (version !== "v2") {
    minSdk = reader.u32();
    maxSdk = reader.u32();
    if (minSdk === null || maxSdk === null)
      return malformed("min/max SDK truncated");
  }
  const attributes = decodeAttributes(reader.lenChunk());
  if (!attributes.ok) return attributes;
  return ok({
    certificates: certificates.value,
    digests: digests.value,
    minSdk,
    maxSdk,
    attributes: attributes.value,
  });
};

/** Decode every signer in a v2/v3/v3.1 scheme block value. */
export const decodeSigners = (
  value: Uint8Array,
  version: ApkSchemeVersion,
): Result<ApkSigner[], ApkSchemeError> => {
  const chunks = elements(
    new LeReader(value).lenChunk(),
    "signers",
    MAX_SIGNERS,
  );
  if (!chunks.ok) return chunks;
  const signers: ApkSigner[] = [];
  for (const [index, chunk] of chunks.value.entries()) {
    const signedData = new LeReader(chunk).lenChunk();
    if (signedData === null)
      return malformed(`signer ${String(index)} has no signed data`);
    const signer = decodeSignedData(signedData, version);
    if (!signer.ok)
      return signer.error.kind === "malformed-signer"
        ? malformed(`signer ${String(index)}: ${signer.error.detail}`)
        : signer;
    signers.push(signer.value);
  }
  return ok(signers);
};

/** One node of a v3 proof-of-rotation lineage (oldest first). */
export interface ApkLineageNode {
  /** X.509 certificate DER of the signer at this level. */
  readonly certificate: Uint8Array;
  /**
   * Capability flags RETAINED by this node's own certificate after the
   * rotation (installed data, shared UID, permission, rollback, auth) — the
   * per-certificate flags Android keeps in SigningDetails.pastSigningCertificates.
   */
  readonly flags: number;
}

/**
 * Decode the v3 proof-of-rotation attribute value (apksig
 * V3SigningCertificateLineage): `u32 version` (must be 1) then length-prefixed
 * nodes, each `lp(signedData{ lp(certificate), u32 sigAlgorithm }) | u32 flags |
 * u32 sigAlgorithm | lp(signature)`. Node signatures are NOT verified: this is
 * the lineage the APK declares.
 */
export const decodeRotationLineage = (
  value: Uint8Array,
): Result<ApkLineageNode[], ApkSchemeError> => {
  const reader = new LeReader(value);
  const version = reader.u32();
  if (version === null) return malformed("lineage version missing");
  if (version !== LINEAGE_VERSION)
    return malformed(`unsupported lineage version ${String(version)}`);
  const nodes: ApkLineageNode[] = [];
  while (reader.remaining > 0) {
    if (nodes.length >= MAX_LINEAGE_NODES)
      return err({
        kind: "budget-exceeded",
        resource: "lineage-nodes",
        limit: MAX_LINEAGE_NODES,
      });
    const node = reader.lenChunk();
    if (node === null) return malformed("lineage node truncated");
    const nodeReader = new LeReader(node);
    const signedData = nodeReader.lenChunk();
    const flags = nodeReader.u32();
    if (signedData === null || flags === null)
      return malformed("lineage node malformed");
    const certificate = new LeReader(signedData).lenChunk();
    if (certificate === null) return malformed("lineage certificate missing");
    nodes.push({ certificate, flags });
  }
  return ok(nodes);
};

/** Map a signature-algorithm id to the content-digest algorithm it uses. */
export const contentDigestAlgorithm = (
  algorithmId: number,
): "sha256" | "sha512" | "verity-sha256" | null => {
  switch (algorithmId) {
    case 0x0101: // RSASSA-PSS SHA2-256
    case 0x0103: // RSASSA-PKCS1-v1_5 SHA2-256
    case 0x0201: // ECDSA SHA2-256
    case 0x0301: // DSA SHA2-256
      return "sha256";
    case 0x0102: // RSASSA-PSS SHA2-512
    case 0x0104: // RSASSA-PKCS1-v1_5 SHA2-512
    case 0x0202: // ECDSA SHA2-512
      return "sha512";
    case 0x0421: // RSASSA-PKCS1-v1_5 SHA2-256 over the verity tree
    case 0x0423: // ECDSA SHA2-256 over the verity tree
    case 0x0425: // DSA SHA2-256 over the verity tree
      return "verity-sha256";
    default:
      return null;
  }
};
