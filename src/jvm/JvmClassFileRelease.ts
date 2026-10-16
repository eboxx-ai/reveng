/** Identity of REA's in-process JVM class-file reader (no external engine). */
export const JVM_PROVIDER_IDENTITY = {
  id: "jvm-class-file",
  name: "REA JVM class-file reader",
  version: null,
} as const;

export const JVM_LIMITS = {
  /** A single class file far exceeding this is rejected before allocation. */
  inputBytes: 32 * 1024 * 1024,
  /**
   * Inline result ceiling. Input bounds alone do not bound the projected
   * result: a crafted class can declare millions of fixed-stride table entries
   * that expand into a far larger JSON object. Reject past this budget rather
   * than returning oversized Evidence, mirroring the Go/Rust in-process readers.
   */
  outputBytes: 8 * 1024 * 1024,
  /**
   * Ceiling on total decoded debug-table entries across the class, checked by a
   * cheap pre-count before any entry object is allocated. Input bounds alone do
   * not bound materialization: a crafted class near `inputBytes` can declare
   * millions of fixed-stride entries that expand ~50x as JS objects (measured
   * ~1.5 GiB RSS before this guard). Derived from `outputBytes` and the smallest
   * per-entry JSON (~32 bytes), so an accepted class also stays near the output
   * budget; a larger class is refused up front, not after allocation.
   */
  maxDebugEntries: 262_144,
  /** Ceiling on a selected JAR's size (its digest is streamed, not retained). */
  archiveBytes: 512 * 1024 * 1024,
  /** Ceiling on a JAR's central-directory metadata read. */
  archiveMetadataBytes: 16 * 1024 * 1024,
} as const;
