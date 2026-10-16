/**
 * Detect v1 (JAR) signing from the ZIP central directory: the presence of
 * `META-INF/MANIFEST.MF`, one or more `*.SF` signature files, and their
 * `*.(RSA|DSA|EC)` PKCS#7 signature blocks. This answers "is the APK v1-signed,
 * and is it v1-only (strippable)?" without parsing the PKCS#7 itself — signer
 * certificate extraction from the block is a layered follow-up.
 *
 * Dependency-free and bounded: central-directory records are walked within the
 * declared directory extent and entry count; a record running past it is a
 * tagged error rather than a silently shorter list. Only top-level `META-INF/`
 * names are decoded and retained (selected by comparing raw bytes), capped at a
 * format-justified count, so memory does not grow with the archive's total
 * entry count (up to ~11M records in a 512 MiB Zip64 file).
 */
import { type Result, err, ok } from "../result.js";

const CD_SIGNATURE = 0x02014b50;
const CD_FIXED_SIZE = 46;

export type ApkCentralDirectoryError =
  | {
      readonly kind: "malformed-central-directory";
      readonly offset: number;
      readonly detail: string;
    }
  | {
      readonly kind: "budget-exceeded";
      readonly resource: "meta-inf-entries";
      readonly limit: number;
    };

/**
 * Top-level `META-INF/` entries retained. A signed APK holds a manifest plus
 * one `.SF` and one block per v1 signer; thousands is already pathological.
 */
export const MAX_META_INF_ENTRIES = 4096;

const META_INF_BYTES = Uint8Array.from(
  [..."META-INF/"].map((c) => c.charCodeAt(0)),
);

/** True when the raw name is `META-INF/<name>` with no further `/`. */
const isTopLevelMetaInf = (
  bytes: Uint8Array,
  start: number,
  length: number,
): boolean => {
  if (length <= META_INF_BYTES.length) return false;
  for (let i = 0; i < META_INF_BYTES.length; i += 1)
    if (bytes[start + i] !== META_INF_BYTES[i]) return false;
  for (let i = start + META_INF_BYTES.length; i < start + length; i += 1)
    if (bytes[i] === 0x2f) return false;
  return true;
};

export interface ApkV1Signature {
  readonly present: boolean;
  readonly hasManifest: boolean;
  /** `META-INF/*.SF` signature files. */
  readonly signatureFiles: readonly string[];
  /** `META-INF/*.(RSA|DSA|EC)` PKCS#7 signature blocks. */
  readonly blockFiles: readonly string[];
}

const NAME_DECODER = new TextDecoder("utf-8", { fatal: false });

/**
 * Walk every central-directory record within the declared extent and count,
 * returning only the top-level `META-INF/` names. A record that runs past the
 * declared extent is an error, not a silently shorter list: a partial walk
 * would turn "unknown" into "absent".
 */
export const centralDirectoryMetaInfNames = (
  bytes: Uint8Array,
  centralDirectoryOffset: number,
  centralDirectorySize: number,
  totalEntries: number,
): Result<string[], ApkCentralDirectoryError> => {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const end = Math.min(
    bytes.length,
    centralDirectoryOffset + centralDirectorySize,
  );
  const names: string[] = [];
  let at = centralDirectoryOffset;
  for (let i = 0; i < totalEntries; i += 1) {
    if (at + CD_FIXED_SIZE > end)
      return err({
        kind: "malformed-central-directory",
        offset: at,
        detail: `central directory ends after ${String(i)} of ${String(totalEntries)} records`,
      });
    if (dv.getUint32(at, true) !== CD_SIGNATURE)
      return err({
        kind: "malformed-central-directory",
        offset: at,
        detail: "central-directory record signature mismatch",
      });
    const nameLength = dv.getUint16(at + 28, true);
    const extraLength = dv.getUint16(at + 30, true);
    const commentLength = dv.getUint16(at + 32, true);
    const nameStart = at + CD_FIXED_SIZE;
    if (nameStart + nameLength > end)
      return err({
        kind: "malformed-central-directory",
        offset: nameStart,
        detail: "central-directory file name runs past the directory",
      });
    if (isTopLevelMetaInf(bytes, nameStart, nameLength)) {
      if (names.length >= MAX_META_INF_ENTRIES)
        return err({
          kind: "budget-exceeded",
          resource: "meta-inf-entries",
          limit: MAX_META_INF_ENTRIES,
        });
      names.push(
        NAME_DECODER.decode(bytes.subarray(nameStart, nameStart + nameLength)),
      );
    }
    at = nameStart + nameLength + extraLength + commentLength;
  }
  // An under-declared record count would silently hide entries (and so v1
  // signing): the walk must consume exactly the declared directory.
  if (at !== end)
    return err({
      kind: "malformed-central-directory",
      offset: at,
      detail: `${String(end - at)} bytes of the declared central directory remain after ${String(totalEntries)} records`,
    });
  return ok(names);
};

const META_INF = "META-INF/";
const BLOCK_SUFFIX = /\.(RSA|DSA|EC)$/;

/** Classify central-directory names into the v1 (JAR) signing facts. */
export const detectV1Signature = (names: readonly string[]): ApkV1Signature => {
  const metaInf = names.filter(
    (name) =>
      name.startsWith(META_INF) && !name.slice(META_INF.length).includes("/"),
  );
  // Case-sensitive throughout, as apksig matches JAR signature entries.
  const signatureFiles = metaInf.filter((name) => name.endsWith(".SF"));
  const blockFiles = metaInf.filter((name) => BLOCK_SUFFIX.test(name));
  const hasManifest = names.includes("META-INF/MANIFEST.MF");
  return {
    present: signatureFiles.length > 0 && blockFiles.length > 0,
    hasManifest,
    signatureFiles,
    blockFiles,
  };
};
