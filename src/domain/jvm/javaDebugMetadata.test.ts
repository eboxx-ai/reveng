import { describe, expect, it } from "vitest";

import { CONSTANT_TAG, parseJavaClassFile } from "./javaClassFile.js";
import {
  projectDebugOutput,
  decodeClassDebugMetadata,
} from "./javaDebugMetadata.js";

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
    const bytes = [...text].map((c) => c.charCodeAt(0));
    return this.u2(bytes.length).raw(bytes);
  }
  raw(bytes: readonly number[]): this {
    this.parts.push(...bytes);
    return this;
  }
  attr(nameIndex: number, info: readonly number[]): this {
    return this.u2(nameIndex).u4(info.length).raw(info);
  }
  bytes(): Uint8Array {
    return Uint8Array.from(this.parts);
  }
}

/**
 * Shared pool (1-based): 1 "run", 2 "()V", 3 "Code", 4 "LineNumberTable",
 * 5 "LocalVariableTable", 6 "x", 7 "I", 8 "SourceFile", 9 "Example.java",
 * 10 "Example", 11 Class->10, 12 "SourceDebugExtension".
 */
const pool = (): Blob =>
  new Blob()
    .u4(0xcafebabe)
    .u2(0) // minor
    .u2(52) // major (Java 8)
    .u2(13)
    .u1(CONSTANT_TAG.utf8)
    .utf8("run")
    .u1(CONSTANT_TAG.utf8)
    .utf8("()V")
    .u1(CONSTANT_TAG.utf8)
    .utf8("Code")
    .u1(CONSTANT_TAG.utf8)
    .utf8("LineNumberTable")
    .u1(CONSTANT_TAG.utf8)
    .utf8("LocalVariableTable")
    .u1(CONSTANT_TAG.utf8)
    .utf8("x")
    .u1(CONSTANT_TAG.utf8)
    .utf8("I")
    .u1(CONSTANT_TAG.utf8)
    .utf8("SourceFile")
    .u1(CONSTANT_TAG.utf8)
    .utf8("Example.java")
    .u1(CONSTANT_TAG.utf8)
    .utf8("Example")
    .u1(CONSTANT_TAG.class)
    .u2(10)
    .u1(CONSTANT_TAG.utf8)
    .utf8("SourceDebugExtension");

const lineNumberTable = (entries: readonly [number, number][]): number[] => {
  const b = new Blob().u2(entries.length);
  for (const [pc, line] of entries) b.u2(pc).u2(line);
  return b.parts;
};

const localVariableTable = (
  entries: readonly { startPc: number; length: number; slot: number }[],
): number[] => {
  const b = new Blob().u2(entries.length);
  for (const e of entries) b.u2(e.startPc).u2(e.length).u2(6).u2(7).u2(e.slot);
  return b.parts;
};

const codeAttrInfo = (subAttrs: readonly number[]): number[] =>
  new Blob()
    .u2(1) // max_stack
    .u2(1) // max_locals
    .u4(1) // code_length
    .u1(0xb1) // return
    .u2(0) // exception_table_length
    .raw(subAttrs).parts;

/** access_flags, this/super, no interfaces/fields, one `run()V` method, class attrs. */
const classWith = (methodAttrs: Blob, classAttrs: Blob): Uint8Array => {
  const b = pool()
    .u2(0x0021) // access_flags
    .u2(11) // this_class
    .u2(0) // super_class
    .u2(0) // interfaces
    .u2(0) // fields
    .u2(1) // methods_count
    .u2(0x0001)
    .u2(1)
    .u2(2); // method run ()V
  b.raw(methodAttrs.parts);
  b.raw(classAttrs.parts);
  return b.bytes();
};

const subAttrs = (count: number, body: Blob): Blob =>
  new Blob().u2(count).raw(body.parts);

describe("decodeClassDebugMetadata", () => {
  it("reports a fully debuggable method as present with decoded tables", () => {
    const code = codeAttrInfo(
      subAttrs(
        2,
        new Blob()
          .attr(4, lineNumberTable([[0, 5]]))
          .attr(5, localVariableTable([{ startPc: 0, length: 1, slot: 0 }])),
      ).parts,
    );
    const cls = parseJavaClassFile(
      classWith(
        new Blob().u2(1).attr(3, code),
        new Blob().u2(1).attr(8, [0, 9]),
      ),
    );
    expect(cls.ok).toBe(true);
    if (!cls.ok) return;
    const meta = decodeClassDebugMetadata(cls.value);
    expect(meta.sourceFile).toEqual({
      presence: "present",
      name: "Example.java",
    });
    const method = meta.methods[0]!;
    expect(method.state).toBe("present");
    expect(method.lineNumbers.entries).toEqual([{ startPc: 0, lineNumber: 5 }]);
    expect(method.localVariables.entries[0]).toMatchObject({
      slot: 0,
      name: "x",
      descriptor: "I",
    });
  });

  it("merges multiple LineNumberTable attributes into one table (JVMS §4.7.12)", () => {
    // A Code attribute may carry the table split across several attributes;
    // the full table is their union, not just the first.
    const code = codeAttrInfo(
      subAttrs(
        2,
        new Blob().attr(4, lineNumberTable([[0, 1]])).attr(
          4,
          lineNumberTable([
            [5, 2],
            [9, 3],
          ]),
        ),
      ).parts,
    );
    const cls = parseJavaClassFile(
      classWith(new Blob().u2(1).attr(3, code), new Blob().u2(0)),
    );
    expect(cls.ok).toBe(true);
    if (!cls.ok) return;
    const method = decodeClassDebugMetadata(cls.value).methods[0]!;
    expect(method.lineNumbers.presence).toBe("present");
    expect(method.lineNumbers.declaredCount).toBe(3);
    expect(method.lineNumbers.entries).toEqual([
      { startPc: 0, lineNumber: 1 },
      { startPc: 5, lineNumber: 2 },
      { startPc: 9, lineNumber: 3 },
    ]);
  });

  it("flags a local-variable scope that lies outside the method code length", () => {
    // codeAttrInfo sets code_length = 1.
    const code = codeAttrInfo(
      subAttrs(
        1,
        new Blob().attr(
          5,
          localVariableTable([
            { startPc: 0, length: 1, slot: 0 }, // within [0,1]
            { startPc: 0, length: 5, slot: 1 }, // extends past code_length
          ]),
        ),
      ).parts,
    );
    const cls = parseJavaClassFile(
      classWith(new Blob().u2(1).attr(3, code), new Blob().u2(0)),
    );
    expect(cls.ok).toBe(true);
    if (!cls.ok) return;
    const entries = decodeClassDebugMetadata(cls.value).methods[0]!
      .localVariables.entries;
    expect(entries[0]!.outOfRange).toBe(false);
    expect(entries[1]!.outOfRange).toBe(true);
  });
});

describe("decodeClassDebugMetadata — states and edge cases", () => {
  it("surfaces reused local slots without collapsing the entries", () => {
    const code = codeAttrInfo(
      subAttrs(
        1,
        new Blob().attr(
          5,
          localVariableTable([
            { startPc: 0, length: 1, slot: 1 },
            { startPc: 2, length: 1, slot: 1 },
          ]),
        ),
      ).parts,
    );
    const cls = parseJavaClassFile(
      classWith(new Blob().u2(1).attr(3, code), new Blob().u2(0)),
    );
    expect(cls.ok).toBe(true);
    if (!cls.ok) return;
    const method = decodeClassDebugMetadata(cls.value).methods[0]!;
    expect(method.localVariables.entries).toHaveLength(2);
    expect(method.reusedSlots).toEqual([1]);
    expect(method.state).toBe("partial"); // locals present, line table absent
  });

  it("classifies a body with no debug tables as stripped", () => {
    const code = codeAttrInfo(subAttrs(0, new Blob()).parts);
    const cls = parseJavaClassFile(
      classWith(new Blob().u2(1).attr(3, code), new Blob().u2(0)),
    );
    expect(cls.ok).toBe(true);
    if (!cls.ok) return;
    expect(decodeClassDebugMetadata(cls.value).methods[0]!.state).toBe(
      "stripped",
    );
  });

  it("classifies a method with no Code attribute as not-applicable", () => {
    const cls = parseJavaClassFile(
      classWith(new Blob().u2(0), new Blob().u2(0)),
    );
    expect(cls.ok).toBe(true);
    if (!cls.ok) return;
    const method = decodeClassDebugMetadata(cls.value).methods[0]!;
    expect(method.hasCode).toBe(false);
    expect(method.state).toBe("not-applicable");
  });

  it("marks a line table malformed when it declares more entries than its bytes hold", () => {
    // declares 5 entries but supplies only one (4 bytes)
    const shortTable = new Blob().u2(5).u2(0).u2(7).parts;
    const code = codeAttrInfo(
      subAttrs(1, new Blob().attr(4, shortTable)).parts,
    );
    const cls = parseJavaClassFile(
      classWith(new Blob().u2(1).attr(3, code), new Blob().u2(0)),
    );
    expect(cls.ok).toBe(true);
    if (!cls.ok) return;
    const method = decodeClassDebugMetadata(cls.value).methods[0]!;
    expect(method.lineNumbers.presence).toBe("malformed");
    expect(method.lineNumbers.declaredCount).toBe(5);
    expect(method.lineNumbers.entries).toEqual([{ startPc: 0, lineNumber: 7 }]); // partial fact kept
    expect(method.state).toBe("malformed");
  });

  it("keeps SourceDebugExtension opaque, reporting only presence and size", () => {
    const sde = [..."SMAP"].map((c) => c.charCodeAt(0));
    const cls = parseJavaClassFile(
      classWith(new Blob().u2(0), new Blob().u2(1).attr(12, sde)),
    );
    expect(cls.ok).toBe(true);
    if (!cls.ok) return;
    const meta = decodeClassDebugMetadata(cls.value);
    expect(meta.sourceDebugExtension).toEqual({
      presence: "present",
      byteLength: 4,
    });
  });

  it("reports an absent SourceFile rather than inventing one", () => {
    const cls = parseJavaClassFile(
      classWith(new Blob().u2(0), new Blob().u2(0)),
    );
    expect(cls.ok).toBe(true);
    if (!cls.ok) return;
    expect(decodeClassDebugMetadata(cls.value).sourceFile).toEqual({
      presence: "absent",
      name: null,
    });
  });

  it("marks a SourceFile whose length is not exactly u2 as malformed", () => {
    // A 3-byte SourceFile attribute (JVMS fixes it at a single u2 index).
    const cls = parseJavaClassFile(
      classWith(new Blob().u2(0), new Blob().u2(1).attr(8, [0, 9, 0])),
    );
    expect(cls.ok).toBe(true);
    if (!cls.ok) return;
    expect(decodeClassDebugMetadata(cls.value).sourceFile).toEqual({
      presence: "malformed",
      name: null,
    });
  });
});

describe("projectDebugOutput", () => {
  it("sums declared table entries plus one per method, without decoding them", () => {
    const code = codeAttrInfo(
      subAttrs(
        2,
        new Blob()
          .attr(
            4,
            lineNumberTable([
              [0, 5],
              [1, 6],
              [2, 7],
            ]),
          )
          .attr(5, localVariableTable([{ startPc: 0, length: 1, slot: 0 }])),
      ).parts,
    );
    const cls = parseJavaClassFile(
      classWith(new Blob().u2(1).attr(3, code), new Blob().u2(0)),
    );
    expect(cls.ok).toBe(true);
    if (!cls.ok) return;
    // 1 method + 3 line entries + 1 local entry
    expect(projectDebugOutput(cls.value, 1000).entries).toBe(5);
  });

  it("clamps a lying declared count to the bytes actually present", () => {
    // Declared count 1000, but only two 4-byte entries follow; capacity wins.
    const lyingTable = new Blob().u2(1000).u2(0).u2(5).u2(1).u2(6).parts;
    const code = codeAttrInfo(
      subAttrs(1, new Blob().attr(4, lyingTable)).parts,
    );
    const cls = parseJavaClassFile(
      classWith(new Blob().u2(1).attr(3, code), new Blob().u2(0)),
    );
    expect(cls.ok).toBe(true);
    if (!cls.ok) return;
    expect(projectDebugOutput(cls.value, 1000).entries).toBe(1 + 2); // method + clamped entries
  });

  it("charges every reference to a shared name, as serialization would expand it", () => {
    const projected = (locals: number) => {
      const code = codeAttrInfo(
        subAttrs(
          1,
          new Blob().attr(
            5,
            localVariableTable(
              Array.from({ length: locals }, (_, slot) => ({
                startPc: 0,
                length: 1,
                slot,
              })),
            ),
          ),
        ).parts,
      );
      const cls = parseJavaClassFile(
        classWith(new Blob().u2(1).attr(3, code), new Blob().u2(0)),
      );
      if (!cls.ok) throw new Error("fixture must parse");
      return projectDebugOutput(cls.value, 1000).encodedBytes;
    };
    // Each extra entry re-references "x" and "I": overhead + "\"x\"" + "\"I\"".
    expect(projected(3) - projected(1)).toBe(2 * (160 + 3 + 3));
  });

  it("stops walking once a running total passes the caller's limit", () => {
    const code = codeAttrInfo(
      subAttrs(
        1,
        new Blob().attr(
          5,
          localVariableTable(
            Array.from({ length: 50 }, (_, slot) => ({
              startPc: 0,
              length: 1,
              slot,
            })),
          ),
        ),
      ).parts,
    );
    const cls = parseJavaClassFile(
      classWith(new Blob().u2(1).attr(3, code), new Blob().u2(0)),
    );
    expect(cls.ok).toBe(true);
    if (!cls.ok) return;
    const full = projectDebugOutput(cls.value, 1000);
    expect(full.entries).toBe(51);
    const stopped = projectDebugOutput(cls.value, 1000, {
      entries: Number.POSITIVE_INFINITY,
      encodedBytes: 5000,
    });
    // Over the limit, but well short of the full walk.
    expect(stopped.encodedBytes).toBeGreaterThan(5000);
    expect(stopped.encodedBytes).toBeLessThan(full.encodedBytes);
  });

  it("stops framing at the retained-attribute budget", () => {
    const code = codeAttrInfo(
      subAttrs(
        3,
        new Blob()
          .attr(4, lineNumberTable([]))
          .attr(4, lineNumberTable([]))
          .attr(4, lineNumberTable([])),
      ).parts,
    );
    const cls = parseJavaClassFile(
      classWith(new Blob().u2(1).attr(3, code), new Blob().u2(0)),
    );
    expect(cls.ok).toBe(true);
    if (!cls.ok) return;
    expect(projectDebugOutput(cls.value, 2).attributeBudgetExceeded).toBe(true);
    expect(projectDebugOutput(cls.value, 3).attributeBudgetExceeded).toBe(
      false,
    );
  });
});

describe("Code sub-attribute recovery", () => {
  it("keeps a table framed before a malformed sibling and marks unreached tables unread", () => {
    const code = codeAttrInfo(
      new Blob()
        .u2(2)
        .attr(4, lineNumberTable([[0, 5]]))
        // A sibling whose declared length runs past the Code attribute.
        .u2(5)
        .u4(9999).parts,
    );
    const cls = parseJavaClassFile(
      classWith(new Blob().u2(1).attr(3, code), new Blob().u2(0)),
    );
    expect(cls.ok).toBe(true);
    if (!cls.ok) return;
    const method = decodeClassDebugMetadata(cls.value).methods[0]!;
    expect(method.state).toBe("malformed");
    expect(method.lineNumbers.presence).toBe("present");
    expect(method.lineNumbers.entries).toEqual([{ startPc: 0, lineNumber: 5 }]);
    expect(method.localVariables.presence).toBe("unread");
    expect(method.localVariableTypes.presence).toBe("unread");
  });
});
