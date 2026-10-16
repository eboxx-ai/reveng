import { describe, expect, it } from "vitest";

import {
  centralDirectoryMetaInfNames,
  detectV1Signature,
  MAX_META_INF_ENTRIES,
} from "./apkV1Signature.js";

/** A central-directory file header (46 fixed bytes) for one entry name. */
const cdRecord = (name: string): number[] => {
  const nameBytes = [...name].map((c) => c.charCodeAt(0));
  const buf = new Uint8Array(46);
  const view = new DataView(buf.buffer);
  view.setUint32(0, 0x02014b50, true); // signature
  view.setUint16(28, nameBytes.length, true); // file name length
  return [...buf, ...nameBytes];
};

const centralDirectory = (names: readonly string[]): Uint8Array =>
  Uint8Array.from(names.flatMap((name) => cdRecord(name)));

describe("APK v1 (JAR) signature detection", () => {
  const names = [
    "AndroidManifest.xml",
    "classes.dex",
    "META-INF/MANIFEST.MF",
    "META-INF/CERT.SF",
    "META-INF/CERT.RSA",
  ];

  it("walks every record but keeps only top-level META-INF names", () => {
    const all = [...names, "META-INF/services/x.Y", "lib/META-INF/z.SF"];
    const bytes = centralDirectory(all);
    const result = centralDirectoryMetaInfNames(
      bytes,
      0,
      bytes.length,
      all.length,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value).toEqual([
      "META-INF/MANIFEST.MF",
      "META-INF/CERT.SF",
      "META-INF/CERT.RSA",
    ]);
  });

  it("refuses more top-level META-INF entries than a signed archive needs", () => {
    const many = Array.from(
      { length: MAX_META_INF_ENTRIES + 1 },
      (_, i) => `META-INF/F${String(i)}.SF`,
    );
    const bytes = centralDirectory(many);
    const result = centralDirectoryMetaInfNames(
      bytes,
      0,
      bytes.length,
      many.length,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toEqual({
      kind: "budget-exceeded",
      resource: "meta-inf-entries",
      limit: MAX_META_INF_ENTRIES,
    });
  });

  it("detects a v1-signed APK from its META-INF files", () => {
    const bytes = centralDirectory(names);
    const result = centralDirectoryMetaInfNames(
      bytes,
      0,
      bytes.length,
      names.length,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const v1 = detectV1Signature(result.value);
    expect(v1).toEqual({
      present: true,
      hasManifest: true,
      signatureFiles: ["META-INF/CERT.SF"],
      blockFiles: ["META-INF/CERT.RSA"],
    });
  });

  it("refuses a directory that ends before its declared record count", () => {
    const bytes = centralDirectory(names);
    const result = centralDirectoryMetaInfNames(
      bytes,
      0,
      bytes.length - 3,
      names.length,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.kind).toBe("malformed-central-directory");
  });

  it("refuses an under-declared record count instead of hiding entries", () => {
    const bytes = centralDirectory(names);
    const result = centralDirectoryMetaInfNames(bytes, 0, bytes.length, 1);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toMatchObject({
      kind: "malformed-central-directory",
      detail: expect.stringContaining("remain after 1 records") as string,
    });
  });

  it("reports absent v1 signing when no META-INF signature files exist", () => {
    const v1 = detectV1Signature(["classes.dex", "res/layout/main.xml"]);
    expect(v1.present).toBe(false);
    expect(v1.signatureFiles).toEqual([]);
  });
});
