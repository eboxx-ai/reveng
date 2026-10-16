import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { TextReader, Uint8ArrayWriter, ZipWriter } from "@zip.js/zip.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { ApkSignatureProvider } from "./ApkSignatureProvider.js";
import { apkSignatureFailure } from "./apkSignatureFailures.js";

type Report = {
  schemes: Record<
    string,
    {
      present: boolean;
      signers?: {
        certificate: unknown;
        digests: { algorithm: string; matches_apk: boolean | null }[];
      }[];
    }
  >;
  posture: Record<string, unknown>;
};

const zipOf = async (names: readonly string[]): Promise<Uint8Array> => {
  const writer = new ZipWriter(new Uint8ArrayWriter());
  for (const name of names) await writer.add(name, new TextReader("x"));
  return writer.close();
};

const u16 = (v: number): number[] => [v & 0xff, (v >> 8) & 0xff];
const u32 = (v: number): number[] => [
  v & 0xff,
  (v >> 8) & 0xff,
  (v >> 16) & 0xff,
  (v >>> 24) & 0xff,
];
const u64 = (v: number): number[] => [...u32(v), ...u32(0)];
const lp = (b: readonly number[]): number[] => [...u32(b.length), ...b];
const seq = (els: readonly (readonly number[])[]): number[] =>
  lp(els.flatMap((e) => lp(e)));

/** [entries][signing block with the given pairs][central directory][EOCD]. */
const syntheticSigned = (
  pairs: readonly { readonly id: number; readonly value: Uint8Array }[],
  options: {
    corruptLeadingSize?: boolean;
    cdEntries?: number;
    gapBeforeEocd?: number;
  } = {},
): Uint8Array => {
  const entries = Buffer.from(Array.from({ length: 64 }, (_, i) => i & 0xff));
  const framed = Buffer.concat(
    pairs.flatMap((p) => [
      Buffer.from([...u64(4 + p.value.length), ...u32(p.id)]),
      p.value,
    ]),
  );
  const size = framed.length + 8 + 16;
  const block = Buffer.concat([
    Buffer.from(u64(size)),
    framed,
    Buffer.from(u64(size)),
    Buffer.from("APK Sig Block 42", "latin1"),
  ]);
  if (options.corruptLeadingSize) block[0] = 0xff;
  // An empty central directory unless a test declares (bogus) records in it.
  const cd =
    options.cdEntries === undefined
      ? Buffer.alloc(0)
      : Buffer.from([0x50, 0x4b, 0x01, 0x02, 0, 0, 0, 0]);
  const gap = Buffer.alloc(options.gapBeforeEocd ?? 0);
  const cdOffset = entries.length + block.length;
  const records = options.cdEntries ?? 0;
  const eocd = Buffer.from([
    ...u32(0x06054b50),
    ...u16(0),
    ...u16(0),
    ...u16(records),
    ...u16(records),
    ...u32(cd.length),
    ...u32(cdOffset),
    ...u16(0),
  ]);
  return Uint8Array.from(Buffer.concat([entries, block, cd, gap, eocd]));
};

const V2 = 0x7109871a;
const V31 = 0x1b93ad61;

const BOGUS_DIGEST = [
  ...u32(0x0103),
  ...lp(Array.from({ length: 32 }, () => 0xab)),
];
const BOGUS_CERT = [0x30, 0x03, 1, 2, 3];

/** A v2 value with one signer: bogus certificate bytes and a bogus SHA-256 digest. */
const bogusV2Value = (): Uint8Array =>
  Uint8Array.from(
    seq([lp([...seq([BOGUS_DIGEST]), ...seq([BOGUS_CERT]), ...seq([])])]),
  );

/** A v3-layout value whose one signer carries the given attributes. */
const v3Value = (attributes: readonly (readonly number[])[]): Uint8Array =>
  Uint8Array.from(
    seq([
      lp([
        ...seq([BOGUS_DIGEST]),
        ...seq([BOGUS_CERT]),
        ...u32(28),
        ...u32(0x7fffffff),
        ...seq(attributes),
      ]),
    ]),
  );

/** Length-prefix a large buffer without spreading it into a number array. */
const lpBuf = (bytes: Uint8Array): Buffer =>
  Buffer.concat([Buffer.from(u32(bytes.length)), bytes]);

let dir: string;
const provider = new ApkSignatureProvider();
beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "rea-apk-sig-"));
});
afterAll(async () => {
  await provider.close();
  await rm(dir, { recursive: true, force: true });
});
const write = async (
  name: string,
  bytes: Uint8Array | string,
): Promise<string> => {
  const path = join(dir, name);
  await writeFile(path, bytes);
  return path;
};
const reportOf = async (path: string): Promise<Report> => {
  const result = await provider.inspect({ path });
  if (!result.ok) throw new Error(`expected ok: ${result.error.message}`);
  return result.value.result as Report;
};

describe("ApkSignatureProvider without the Android SDK", () => {
  it("reports an unsigned ZIP as having no scheme", async () => {
    const r = await reportOf(
      await write(
        "unsigned.apk",
        await zipOf(["classes.dex", "AndroidManifest.xml"]),
      ),
    );
    expect(Object.values(r.schemes).some((s) => s.present)).toBe(false);
    expect(r.posture.strongest_scheme).toBe("none");
    expect(r.posture.self_consistent).toBeNull();
    expect(r.posture.v1_only).toBe(false);
  });

  it("detects v1-only signing from META-INF entries", async () => {
    const r = await reportOf(
      await write(
        "v1.apk",
        await zipOf([
          "classes.dex",
          "META-INF/MANIFEST.MF",
          "META-INF/CERT.SF",
          "META-INF/CERT.RSA",
        ]),
      ),
    );
    expect(r.schemes.v1!.present).toBe(true);
    expect(r.posture.v1_only).toBe(true);
    expect(r.posture.strongest_scheme).toBe("v1");
  });

  it("decodes a v2 signer, keeps an unparseable certificate null, and flags a digest mismatch", async () => {
    const r = await reportOf(
      await write(
        "v2.apk",
        syntheticSigned([{ id: V2, value: bogusV2Value() }]),
      ),
    );
    expect(r.schemes.v2!.present).toBe(true);
    const signer = r.schemes.v2!.signers![0]!;
    // Identity is the raw-DER fingerprint even when X.509 parsing fails.
    expect(signer.certificate).toEqual({
      sha256_fingerprint: createHash("sha256")
        .update(Uint8Array.from(BOGUS_CERT))
        .digest("hex"),
      subject: null,
      issuer: null,
      serial_number: null,
      not_before: null,
      not_after: null,
      public_key_algorithm: null,
    });
    expect(signer.digests).toEqual([
      { algorithm: "sha256", matches_apk: false },
    ]);
    expect(r.posture.self_consistent).toBe(false);
  });
});

describe("ApkSignatureProvider failure surfaces", () => {
  it("keeps typed reader failures as input errors and defects as adapter errors", () => {
    expect(
      apkSignatureFailure(
        new ArtifactReaderFailure(
          "format",
          "archive entry did not yield bytes",
        ),
        "/x.apk",
      )._tag,
    ).toBe("AnalysisInputError");
    expect(apkSignatureFailure(new RangeError("boom"), "/x.apk")._tag).toBe(
      "ProviderAdapterError",
    );
  });

  it("reports a missing file without leaking the raw errno text", async () => {
    const result = await provider.inspect({ path: join(dir, "absent.apk") });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("AnalysisInputError");
    const text = JSON.stringify(result.error);
    expect(text).toContain("No regular file can be read");
    expect(text).not.toContain("no such file or directory, lstat");
  });

  it("refuses a non-ZIP file as an unsupported target", async () => {
    const result = await provider.inspect({
      path: await write("plain.bin", "not an archive at all"),
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("AnalysisUnsupportedTargetError");
  });

  it("reports a malformed signing block as an input error", async () => {
    const result = await provider.inspect({
      path: await write(
        "bad.apk",
        syntheticSigned([{ id: V2, value: bogusV2Value() }], {
          corruptLeadingSize: true,
        }),
      ),
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("AnalysisInputError");
  });

  it("reports a malformed declared lineage instead of dropping it", async () => {
    const lineage = [...u32(0x3ba06f8c), ...u32(1), ...u32(999)];
    const r = (await reportOf(
      await write(
        "lineage.apk",
        syntheticSigned([{ id: V31, value: v3Value([lineage]) }]),
      ),
    )) as unknown as {
      schemes: { "v3.1": { signers: { rotation: unknown }[] } };
      posture: { strongest_scheme: string };
    };
    expect(r.posture.strongest_scheme).toBe("v3.1");
    expect(r.schemes["v3.1"].signers[0]!.rotation).toEqual({
      present: true,
      lineage: [],
      decode_error: "lineage node truncated",
    });
  });

  it("names v3.1 when its block is malformed", async () => {
    const result = await provider.inspect({
      path: await write(
        "bad31.apk",
        syntheticSigned([{ id: V31, value: Uint8Array.from(u32(77)) }]),
      ),
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(JSON.stringify(result.error)).toContain("Scheme v3.1 block");
  });

  it("refuses a central directory that cannot be walked", async () => {
    const result = await provider.inspect({
      path: await write(
        "badcd.apk",
        syntheticSigned([{ id: V2, value: bogusV2Value() }], { cdEntries: 3 }),
      ),
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("AnalysisInputError");
    expect(JSON.stringify(result.error)).toContain(
      "Malformed ZIP central directory",
    );
  });

  it("refuses an under-declared entry count rather than hiding v1 signing", async () => {
    const zip = await zipOf([
      "classes.dex",
      "META-INF/MANIFEST.MF",
      "META-INF/CERT.SF",
      "META-INF/CERT.RSA",
    ]);
    const eocd = zip.length - 22;
    zip.set(u16(1), eocd + 8);
    zip.set(u16(1), eocd + 10);
    const result = await provider.inspect({
      path: await write("undercount.apk", zip),
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("AnalysisInputError");
  });

  it("says why the digest was not recomputed when the EOCD does not follow the directory", async () => {
    const result = await provider.inspect({
      path: await write(
        "gap.apk",
        syntheticSigned([{ id: V2, value: bogusV2Value() }], {
          gapBeforeEocd: 4,
        }),
      ),
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect((result.value.result as Report).posture.self_consistent).toBeNull();
    expect(result.value.limitations.at(-1)).toContain(
      "not immediately followed by the end-of-central-directory",
    );
  });

  it("refuses a report that would exceed the output budget before building it", async () => {
    const hugeCert = new Uint8Array(4.5 * 1024 * 1024);
    const signedData = Buffer.concat([
      Buffer.from(seq([BOGUS_DIGEST])),
      lpBuf(lpBuf(hugeCert)),
      Buffer.from(seq([])),
    ]);
    const value = lpBuf(lpBuf(lpBuf(signedData)));
    const result = await provider.inspect({
      path: await write("huge.apk", syntheticSigned([{ id: V2, value }])),
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("AnalysisResourceConstraintError");
    expect(result.error.message).toContain("output budget");
  });
});
