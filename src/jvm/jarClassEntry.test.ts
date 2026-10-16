import { describe, expect, it } from "vitest";

import {
  classifyJarEntry,
  normalizeJarEntryPath,
  resolveJarSelection,
} from "./jarClassEntry.js";

describe("classifyJarEntry", () => {
  it("recognizes the base entry", () => {
    expect(
      classifyJarEntry("com/example/Foo.class", "com/example/Foo.class"),
    ).toEqual({ release: null, path: "com/example/Foo.class" });
  });

  it("recognizes a versioned override and its release", () => {
    expect(
      classifyJarEntry(
        "META-INF/versions/17/com/example/Foo.class",
        "com/example/Foo.class",
      ),
    ).toEqual({
      release: 17,
      path: "META-INF/versions/17/com/example/Foo.class",
    });
  });

  it("ignores unrelated members and malformed version segments", () => {
    expect(
      classifyJarEntry("com/example/Bar.class", "com/example/Foo.class"),
    ).toBeUndefined();
    expect(
      classifyJarEntry(
        "META-INF/versions/x/com/example/Foo.class",
        "com/example/Foo.class",
      ),
    ).toBeUndefined();
    expect(
      classifyJarEntry(
        "META-INF/versions/17/com/example/Other.class",
        "com/example/Foo.class",
      ),
    ).toBeUndefined();
  });
});

describe("resolveJarSelection", () => {
  const base = { release: null, path: "Foo.class" } as const;
  const v17 = { release: 17, path: "META-INF/versions/17/Foo.class" } as const;
  const v21 = { release: 21, path: "META-INF/versions/21/Foo.class" } as const;

  it("selects the base entry when no release is requested", () => {
    expect(resolveJarSelection([base, v17], undefined)).toEqual({
      ok: true,
      path: "Foo.class",
      release: null,
    });
  });

  it("selects the exact requested release, never a neighbor", () => {
    expect(resolveJarSelection([base, v17, v21], 17)).toEqual({
      ok: true,
      path: "META-INF/versions/17/Foo.class",
      release: 17,
    });
  });

  it("refuses a requested release that is absent, listing alternatives", () => {
    expect(resolveJarSelection([base, v17, v21], 11)).toEqual({
      ok: false,
      reason: "release-absent",
      available: [17, 21],
    });
  });

  it("requires an explicit release when only versioned entries exist", () => {
    expect(resolveJarSelection([v17, v21], undefined)).toEqual({
      ok: false,
      reason: "release-absent",
      available: [17, 21],
    });
  });

  it("reports not-found when the entry is absent entirely", () => {
    expect(resolveJarSelection([], undefined)).toEqual({
      ok: false,
      reason: "not-found",
      available: [],
    });
  });
});

describe("normalizeJarEntryPath", () => {
  it("applies the ZIP reader's logical-path rule to the request", () => {
    expect(normalizeJarEntryPath("./Foo.class")).toBe("Foo.class");
    expect(normalizeJarEntryPath("././a/Foo.class")).toBe("a/Foo.class");
    expect(normalizeJarEntryPath("/a\\Foo.class")).toBe("a/Foo.class");
    expect(normalizeJarEntryPath("a/./Foo.class")).toBe("a/./Foo.class");
  });
});
