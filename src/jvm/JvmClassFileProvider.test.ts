import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  TextReader,
  Uint8ArrayReader,
  Uint8ArrayWriter,
  ZipWriter,
} from "@zip.js/zip.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { JvmClassFileProvider } from "./JvmClassFileProvider.js";
import { CONSTANT_TAG } from "../domain/jvm/javaClassFile.js";

/** Minimal valid class named com/example/Foo at the given major version. */
const minimalClass = (major: number): Uint8Array => {
  const parts: number[] = [];
  const u1 = (v: number) => parts.push(v & 0xff);
  const u2 = (v: number) => parts.push((v >> 8) & 0xff, v & 0xff);
  const u4 = (v: number) =>
    parts.push((v >>> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff);
  const utf8 = (text: string) => {
    const b = [...text].map((c) => c.charCodeAt(0));
    u2(b.length);
    parts.push(...b);
  };
  u4(0xcafebabe);
  u2(0); // minor
  u2(major);
  u2(6); // constant_pool_count
  u1(CONSTANT_TAG.utf8);
  utf8("<init>");
  u1(CONSTANT_TAG.utf8);
  utf8("()V");
  u1(CONSTANT_TAG.utf8);
  utf8("Code");
  u1(CONSTANT_TAG.utf8);
  utf8("com/example/Foo");
  u1(CONSTANT_TAG.class);
  u2(4);
  u2(0x0021); // access_flags
  u2(5); // this_class
  u2(0); // super_class
  u2(0); // interfaces
  u2(0); // fields
  u2(1); // methods_count
  u2(0x0001);
  u2(1);
  u2(2);
  u2(1);
  u2(3);
  u4(0); // <init>()V, one empty Code attr
  u2(0); // class attributes_count
  return Uint8Array.from(parts);
};

const ENTRY = "com/example/Foo.class";

const buildZip = async (
  files: readonly { name: string; bytes?: Uint8Array; text?: string }[],
): Promise<Uint8Array> => {
  const writer = new ZipWriter(new Uint8ArrayWriter());
  for (const file of files)
    await writer.add(
      file.name,
      file.text === undefined
        ? new Uint8ArrayReader(file.bytes!)
        : new TextReader(file.text),
    );
  return writer.close();
};

const MR_MANIFEST = "Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n";
const PLAIN_MANIFEST = "Manifest-Version: 1.0\r\n\r\n";

let dir: string;
const provider = new JvmClassFileProvider();

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "rea-jvm-jar-"));
});
afterAll(async () => {
  await provider.close();
  await rm(dir, { recursive: true, force: true });
});

const writeJar = async (name: string, bytes: Uint8Array): Promise<string> => {
  const path = join(dir, name);
  await writeFile(path, bytes);
  return path;
};

const mrJar = async (): Promise<string> =>
  writeJar(
    "mr.jar",
    await buildZip([
      { name: "META-INF/MANIFEST.MF", text: MR_MANIFEST },
      { name: ENTRY, bytes: minimalClass(52) },
      {
        name: "META-INF/versions/17/com/example/Foo.class",
        bytes: minimalClass(61),
      },
    ]),
  );

describe("JvmClassFileProvider JAR entry selection", () => {
  it("selects the base entry when no release is requested", async () => {
    const result = await provider.inspect({
      path: await mrJar(),
      entry: ENTRY,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const r = result.value.result as Record<string, unknown>;
    expect(r.container).toBe("jar");
    expect((r.selected_entry as { release: number | null }).release).toBeNull();
    expect((r.class as { internal_name: string }).internal_name).toBe(
      "com/example/Foo",
    );
  });

  it("selects the explicit multi-release override, distinct from the base", async () => {
    const path = await mrJar();
    const base = await provider.inspect({ path, entry: ENTRY });
    const v17 = await provider.inspect({ path, entry: ENTRY, release: 17 });
    expect(base.ok && v17.ok).toBe(true);
    if (!base.ok || !v17.ok) return;
    const v17r = v17.value.result as {
      selected_entry: { release: number; sha256: string };
    };
    const baser = base.value.result as { selected_entry: { sha256: string } };
    expect(v17r.selected_entry.release).toBe(17);
    expect(v17r.selected_entry.sha256).not.toBe(baser.selected_entry.sha256);
  });

  it("refuses a release that is not present", async () => {
    const result = await provider.inspect({
      path: await mrJar(),
      entry: ENTRY,
      release: 11,
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("AnalysisInputError");
  });

  it("reports a missing entry as an input error", async () => {
    const result = await provider.inspect({
      path: await mrJar(),
      entry: "com/example/Nope.class",
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("AnalysisInputError");
  });

  it("refuses a versioned selection when the JAR is not multi-release", async () => {
    const path = await writeJar(
      "plain.jar",
      await buildZip([
        { name: "META-INF/MANIFEST.MF", text: PLAIN_MANIFEST },
        { name: ENTRY, bytes: minimalClass(52) },
        {
          name: "META-INF/versions/17/com/example/Foo.class",
          bytes: minimalClass(61),
        },
      ]),
    );
    const versioned = await provider.inspect({
      path,
      entry: ENTRY,
      release: 17,
    });
    expect(versioned.ok).toBe(false);
    if (versioned.ok) return;
    expect(versioned.error._tag).toBe("AnalysisInputError");
    // The base entry is still selectable on a non-multi-release JAR.
    const base = await provider.inspect({ path, entry: ENTRY });
    expect(base.ok).toBe(true);
  });
});

describe("JvmClassFileProvider JAR safety and format", () => {
  it("fails cleanly when entry is given but the path is not an archive", async () => {
    const loose = await writeJar("Loose.class", minimalClass(52));
    const result = await provider.inspect({ path: loose, entry: ENTRY });
    expect(result.ok).toBe(false);
  });

  it("guides the caller to entry selection when a JAR is given without entry", async () => {
    const result = await provider.inspect({ path: await mrJar() });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("AnalysisUnsupportedTargetError");
    const remediation = (result.error as { remediationAction?: string })
      .remediationAction;
    expect(remediation).toContain("entry");
  });

  it("normalizes a leading slash and backslashes in the requested entry", async () => {
    const path = await mrJar();
    const backslashed = await provider.inspect({
      path,
      entry: "\\com\\example\\Foo.class",
    });
    expect(backslashed.ok).toBe(true);
    if (!backslashed.ok) return;
    const r = backslashed.value.result as {
      selected_entry: { entry: string };
    };
    expect(r.selected_entry.entry).toBe(ENTRY);
  });

  it("selects a './'-prefixed member by either spelling and keeps its archive name visible", async () => {
    const path = await writeJar(
      "dotslash.jar",
      await buildZip([{ name: `./${ENTRY}`, bytes: minimalClass(52) }]),
    );
    for (const entry of [ENTRY, `./${ENTRY}`]) {
      const result = await provider.inspect({ path, entry });
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.value.limitations.join("\n")).toContain(
        JSON.stringify(`./${ENTRY}`),
      );
    }
  });

  it("reports an encrypted matching member as unavailable, not absent", async () => {
    const writer = new ZipWriter(new Uint8ArrayWriter());
    await writer.add(ENTRY, new Uint8ArrayReader(minimalClass(52)), {
      password: "secret",
    });
    const path = await writeJar("encrypted.jar", await writer.close());
    const result = await provider.inspect({ path, entry: ENTRY });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("AnalysisUnsupportedTargetError");
    expect(result.error.message.toLowerCase()).toContain("encrypted");
  });

  it("steers a Mach-O universal binary (shared 0xCAFEBABE magic) to inspect_macho", async () => {
    // Fat header: magic CAFEBABE, nfat_arch = 2 -> u2@6 = 2, below any class major.
    const fat = Uint8Array.from([
      0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
    ]);
    const path = await writeJar("universal.bin", fat);
    const result = await provider.inspect({ path });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("AnalysisUnsupportedTargetError");
    const remediation = (result.error as { remediationAction?: string })
      .remediationAction;
    expect(remediation).toContain("inspect_macho");
  });

  it("refuses to follow a symlinked JAR", async () => {
    const real = await mrJar();
    const link = join(dir, "link.jar");
    await symlink(real, link);
    const result = await provider.inspect({ path: link, entry: ENTRY });
    expect(result.ok).toBe(false);
  });
});
