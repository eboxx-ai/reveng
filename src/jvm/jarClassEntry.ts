/**
 * Multi-release JAR member selection (JAR File Specification, Multi-Release
 * JARs). A class entry `E` may exist as the base `E` and as versioned overrides
 * `META-INF/versions/<N>/E`. Selection is explicit and never silently combines
 * metadata across versions: an omitted release uses the base, and a requested
 * release must match a present versioned entry or the selection is refused with
 * the available alternatives.
 */

/** `release: null` denotes the base (unversioned) entry. */
export interface JarEntryCandidate {
  readonly release: number | null;
  readonly path: string;
}

export type JarSelection =
  | {
      readonly ok: true;
      readonly path: string;
      readonly release: number | null;
    }
  | {
      readonly ok: false;
      readonly reason: "not-found" | "release-absent";
      readonly available: readonly number[];
    };

const VERSIONS_PREFIX = "META-INF/versions/";

/**
 * Canonicalize a caller-supplied JAR member path to the internal form ZIP
 * entries use: forward slashes, no leading slash. A JAR member is identified by
 * exactly this string, so normalization happens once here before any match.
 */
/**
 * Normalise a requested entry the way the ZIP reader forms logical member
 * paths (it owns that rule): forward slashes, no leading `/`, and no leading
 * `./` segments, so the archive's literal `./Foo.class` is selectable.
 */
export const normalizeJarEntryPath = (entry: string): string =>
  entry
    .replace(/\\/g, "/")
    .replace(/^\/+/, "")
    .replace(/^(?:\.\/)+/u, "");

/**
 * Classify an archive member path for the requested class entry: the base entry,
 * a versioned override, or unrelated (`undefined`).
 */
export const classifyJarEntry = (
  memberPath: string,
  entry: string,
): JarEntryCandidate | undefined => {
  if (memberPath === entry) return { release: null, path: memberPath };
  if (!memberPath.startsWith(VERSIONS_PREFIX)) return undefined;
  const rest = memberPath.slice(VERSIONS_PREFIX.length);
  const slash = rest.indexOf("/");
  if (slash <= 0) return undefined;
  const version = rest.slice(0, slash);
  // The JAR spec only honors versioned directories named by an integer >= 9,
  // with no leading zeros; lower or non-canonical numbers are inert resources.
  if (
    !/^[1-9][0-9]*$/.test(version) ||
    Number(version) < 9 ||
    rest.slice(slash + 1) !== entry
  )
    return undefined;
  return { release: Number(version), path: memberPath };
};

/** Resolve which candidate to read for the requested release, or refuse explicitly. */
export const resolveJarSelection = (
  candidates: readonly JarEntryCandidate[],
  requestedRelease: number | undefined,
): JarSelection => {
  if (candidates.length === 0)
    return { ok: false, reason: "not-found", available: [] };
  const available = candidates
    .flatMap((c) => (c.release === null ? [] : [c.release]))
    .sort((a, b) => a - b);
  const base = candidates.find((c) => c.release === null);
  if (requestedRelease === undefined) {
    if (base !== undefined) return { ok: true, path: base.path, release: null };
    // Only versioned entries exist; require an explicit release rather than
    // guessing a version.
    return { ok: false, reason: "release-absent", available };
  }
  const match = candidates.find((c) => c.release === requestedRelease);
  if (match !== undefined)
    return { ok: true, path: match.path, release: requestedRelease };
  // The caller named a release that is not present; never silently fall back.
  return { ok: false, reason: "release-absent", available };
};
