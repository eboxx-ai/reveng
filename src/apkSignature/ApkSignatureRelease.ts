/** Identity of REA's in-process APK signature reader (no external engine, no device). */
export const APK_SIGNATURE_PROVIDER_IDENTITY = {
  id: "apk-signature",
  name: "REA APK signature reader",
  version: null,
} as const;

export const APK_SIGNATURE_LIMITS = {
  /**
   * Whole-APK bounded read; the content digest needs the whole file. Above
   * Play's 200 MB APK ceiling with headroom for sideloaded/system APKs.
   */
  inputBytes: 512 * 1024 * 1024,
  /** Inline result ceiling, projected before materialising and re-checked exactly; refused, not truncated. */
  outputBytes: 8 * 1024 * 1024,
} as const;
