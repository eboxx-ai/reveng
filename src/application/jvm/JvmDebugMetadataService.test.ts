import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { JvmDebugMetadataService } from "./JvmDebugMetadataService.js";
import { JvmClassFileProvider } from "../../jvm/JvmClassFileProvider.js";
import { CONSTANT_TAG } from "../../domain/jvm/javaClassFile.js";

class Blob {
  readonly parts: number[] = [];
  u1(v: number): this {
    this.parts.push(v & 0xff);
    return this;
  }
  u2(v: number): this {
    this.parts.push((v >> 8) & 0xff, v & 0xff);
    return this;
  }
  u4(v: number): this {
    this.parts.push(
      (v >>> 24) & 0xff,
      (v >> 16) & 0xff,
      (v >> 8) & 0xff,
      v & 0xff,
    );
    return this;
  }
  utf8(text: string): this {
    const b = [...text].map((c) => c.charCodeAt(0));
    this.u2(b.length);
    this.parts.push(...b);
    return this;
  }
  raw(bytes: readonly number[]): this {
    // Append without spreading: a large table would overflow the call stack.
    for (const byte of bytes) this.parts.push(byte);
    return this;
  }
  attr(nameIndex: number, info: readonly number[]): this {
    return this.u2(nameIndex).u4(info.length).raw(info);
  }
}

/**
 * A class whose single method's Code carries several near-maximal
 * LineNumberTable attributes, so the projected result far exceeds the inline
 * output budget. Pool: 1 "Code", 2 "LineNumberTable", 3 "Big", 4 Class->3,
 * 5 "m", 6 "()V".
 */
const overBudgetClass = (): Uint8Array => {
  const maxTable = (): number[] => {
    const b = new Blob().u2(0xffff);
    for (let i = 0; i < 0xffff; i += 1) b.u2(i & 0xffff).u2(1);
    return b.parts;
  };
  const code = new Blob()
    .u2(0)
    .u2(0)
    .u4(1)
    .u1(0xb1)
    .u2(0) // max_stack/locals, code, exception table
    .u2(6); // attributes_count: 6 LineNumberTable attrs -> ~393k merged entries
  for (let i = 0; i < 6; i += 1) code.attr(2, maxTable());
  const cls = new Blob()
    .u4(0xcafebabe)
    .u2(0)
    .u2(52)
    .u2(7)
    .u1(CONSTANT_TAG.utf8)
    .utf8("Code")
    .u1(CONSTANT_TAG.utf8)
    .utf8("LineNumberTable")
    .u1(CONSTANT_TAG.utf8)
    .utf8("Big")
    .u1(CONSTANT_TAG.class)
    .u2(3)
    .u1(CONSTANT_TAG.utf8)
    .utf8("m")
    .u1(CONSTANT_TAG.utf8)
    .utf8("()V")
    .u2(0x0021)
    .u2(4)
    .u2(0)
    .u2(0)
    .u2(0)
    .u2(1)
    .u2(0x0001)
    .u2(5)
    .u2(6)
    .u2(1)
    .attr(1, code.parts)
    .u2(0);
  return Uint8Array.from(cls.parts);
};

/** Minimal `Example` class: `<init>()V` with a Code attribute, class-level SourceFile. */
const minimalClass = (): Uint8Array =>
  Uint8Array.from(
    new Blob()
      .u4(0xcafebabe)
      .u2(0)
      .u2(52)
      .u2(8)
      .u1(CONSTANT_TAG.utf8)
      .utf8("<init>")
      .u1(CONSTANT_TAG.utf8)
      .utf8("()V")
      .u1(CONSTANT_TAG.utf8)
      .utf8("Code")
      .u1(CONSTANT_TAG.utf8)
      .utf8("SourceFile")
      .u1(CONSTANT_TAG.utf8)
      .utf8("Example.java")
      .u1(CONSTANT_TAG.utf8)
      .utf8("Example")
      .u1(CONSTANT_TAG.class)
      .u2(6)
      .u2(0x0021)
      .u2(7)
      .u2(0)
      .u2(0)
      .u2(0)
      .u2(1)
      .u2(0x0001)
      .u2(1)
      .u2(2)
      .u2(1)
      .u2(3)
      .u4(0)
      .u2(1)
      .u2(4)
      .u4(2)
      .u2(5).parts,
  );

describe("JvmDebugMetadataService", () => {
  let dir: string;
  const service = new JvmDebugMetadataService(new JvmClassFileProvider());

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "rea-jvm-"));
  });
  afterAll(async () => {
    await service.close();
    await rm(dir, { recursive: true, force: true });
  });

  it("returns Evidence with the selected identity and decoded class facts", async () => {
    const path = join(dir, "Example.class");
    await writeFile(path, minimalClass());
    const result = await service.inspect({ path });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const normalized = result.value.normalized_result as Record<
      string,
      unknown
    >;
    expect((normalized.artifact as { path: string }).path).toBe(path);
    expect((normalized.class as { internal_name: string }).internal_name).toBe(
      "Example",
    );
    expect((normalized.source_file as { name: string }).name).toBe(
      "Example.java",
    );
    expect(result.value.subject?.digest.sha256).toMatch(/^[a-f0-9]{64}$/);
  });

  it("rejects a relative path before any read", async () => {
    const result = await service.inspect({ path: "Example.class" });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("AnalysisInputError");
  });

  it("reports an unsupported target when magic is not a class file", async () => {
    const path = join(dir, "notclass.bin");
    await writeFile(path, Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]));
    const result = await service.inspect({ path });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("AnalysisUnsupportedTargetError");
  });

  it("maps a missing file to an input error, not a producer fault", async () => {
    const result = await service.inspect({ path: join(dir, "absent.class") });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("AnalysisInputError");
  });

  it("rejects a release without an entry at the input boundary", async () => {
    const result = await service.inspect({
      path: join(dir, "Example.class"),
      release: 17,
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("AnalysisInputError");
  });

  it("reports cancellation before any read when the signal is already aborted", async () => {
    const result = await service.inspect(
      { path: join(dir, "Example.class") },
      { signal: AbortSignal.abort() },
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("AnalysisCancelledError");
  });

  it("refuses a class with too many declared table entries before allocating them", async () => {
    const path = join(dir, "Big.class");
    await writeFile(path, overBudgetClass());
    const result = await service.inspect({ path });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("AnalysisResourceConstraintError");
    // The pre-count guard trips, not the post-build output guard.
    expect(result.error.message).toContain("before allocation");
  });
});
