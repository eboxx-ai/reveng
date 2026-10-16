import { describe, expect, it } from "vitest";

import {
  apkSignatureResultSchema,
  deriveApkPosture,
  inspectApkSignatureInputSchema,
} from "./apkSignatureReport.js";

describe("deriveApkPosture", () => {
  const base = {
    v1Present: false,
    v2Present: false,
    v3Present: false,
    v31Present: false,
    sourceStampPresent: false,
    rotationPresent: false,
    schemeSignerFingerprints: [] as (string | null)[][],
    lineageFingerprints: [] as string[],
    selfConsistent: null,
  };

  it("flags v1-only when only JAR signing is present", () => {
    const p = deriveApkPosture({ ...base, v1Present: true });
    expect(p.v1_only).toBe(true);
    expect(p.strongest_scheme).toBe("v1");
    expect(p.schemes_agree_on_signer).toBeNull();
  });

  it("picks the strongest scheme and is not v1-only when v3 is present", () => {
    const p = deriveApkPosture({
      ...base,
      v1Present: true,
      v2Present: true,
      v3Present: true,
      schemeSignerFingerprints: [["aa"], ["aa"]],
    });
    expect(p.v1_only).toBe(false);
    expect(p.strongest_scheme).toBe("v3");
    expect(p.schemes_agree_on_signer).toBe(true);
  });

  it("observes different signers across schemes as disagreement", () => {
    const p = deriveApkPosture({
      ...base,
      v2Present: true,
      v3Present: true,
      schemeSignerFingerprints: [["aa"], ["bb"]],
    });
    expect(p.schemes_agree_on_signer).toBe(false);
  });

  it("keeps observed disagreement separate from a declared rotation", () => {
    const p = deriveApkPosture({
      ...base,
      v2Present: true,
      v3Present: true,
      rotationPresent: true,
      schemeSignerFingerprints: [["old"], ["new"]],
      lineageFingerprints: ["old", "new"],
    });
    expect(p.schemes_agree_on_signer).toBe(false);
    expect(p.signer_change_declared_by_rotation).toBe(true);
  });

  it("does not credit rotation when a signer is missing from the lineage", () => {
    const p = deriveApkPosture({
      ...base,
      v2Present: true,
      v3Present: true,
      rotationPresent: true,
      schemeSignerFingerprints: [["evil"], ["new"]],
      lineageFingerprints: ["old", "new"],
    });
    expect(p.signer_change_declared_by_rotation).toBe(false);
  });

  it("leaves agreement unknown when a signer carries no certificate", () => {
    const p = deriveApkPosture({
      ...base,
      v2Present: true,
      v3Present: true,
      schemeSignerFingerprints: [["aa"], [null]],
    });
    expect(p.schemes_agree_on_signer).toBeNull();
  });

  it("compares signer sets, so an extra signer in one scheme is disagreement", () => {
    const p = deriveApkPosture({
      ...base,
      v2Present: true,
      v3Present: true,
      schemeSignerFingerprints: [["aa", "bb"], ["aa"]],
    });
    expect(p.schemes_agree_on_signer).toBe(false);
    const same = deriveApkPosture({
      ...base,
      v2Present: true,
      v3Present: true,
      schemeSignerFingerprints: [
        ["bb", "aa"],
        ["aa", "bb"],
      ],
    });
    expect(same.schemes_agree_on_signer).toBe(true);
  });

  it("surfaces rotation, source stamp and self-consistency", () => {
    const p = deriveApkPosture({
      ...base,
      v3Present: true,
      rotationPresent: true,
      sourceStampPresent: true,
      schemeSignerFingerprints: [["aa"]],
      selfConsistent: true,
    });
    expect(p.rotation_present).toBe(true);
    expect(p.source_stamp_present).toBe(true);
    expect(p.self_consistent).toBe(true);
  });

  it("accepts only an absolute path; schema is strict", () => {
    expect(
      inspectApkSignatureInputSchema.safeParse({ path: "/a/b.apk" }).success,
    ).toBe(true);
    expect(
      inspectApkSignatureInputSchema.safeParse({ path: "/a/b.apk", extra: 1 })
        .success,
    ).toBe(false);
    // The result schema rejects unknown keys (sanity that strictObject holds).
    expect(apkSignatureResultSchema.safeParse({}).success).toBe(false);
  });
});
