import { describe, expect, it } from "vitest";

import type { MethodDebugMetadata } from "./javaDebugMetadata.js";
import { buildJavaDebugMetadataEvidence } from "./javaDebugMetadataEvidence.js";

const absent = { presence: "absent", declaredCount: 0, entries: [] } as const;

const method = (
  name: string | null,
  descriptor: string | null,
  state: MethodDebugMetadata["state"],
): MethodDebugMetadata => ({
  name,
  descriptor,
  state,
  hasCode: state !== "not-applicable",
  lineNumbers: absent,
  localVariables: absent,
  localVariableTypes: absent,
  reusedSlots: [],
});

describe("buildJavaDebugMetadataEvidence", () => {
  it("orders methods by name then descriptor, with unnamed entries last", () => {
    const evidence = buildJavaDebugMetadataEvidence({
      sourceFile: { presence: "absent", name: null },
      sourceDebugExtension: { presence: "absent", byteLength: 0 },
      methods: [
        method(null, "()V", "stripped"),
        method("run", "(I)V", "present"),
        method("run", "()V", "present"),
        method("compute", "()I", "partial"),
      ],
    });
    expect(evidence.methods.map((m) => [m.name, m.descriptor])).toEqual([
      ["compute", "()I"],
      ["run", "()V"],
      ["run", "(I)V"],
      [null, "()V"],
    ]);
  });

  it("tallies coverage from the examined method states", () => {
    const evidence = buildJavaDebugMetadataEvidence({
      sourceFile: { presence: "present", name: "A.java" },
      sourceDebugExtension: { presence: "absent", byteLength: 0 },
      methods: [
        method("a", "()V", "present"),
        method("b", "()V", "present"),
        method("c", "()V", "stripped"),
        method("d", "()V", "partial"),
        method("e", "()V", "malformed"),
        method("f", "()V", "not-applicable"),
      ],
    });
    expect(evidence.coverage).toEqual({
      total: 6,
      present: 2,
      partial: 1,
      stripped: 1,
      malformed: 1,
      notApplicable: 1,
    });
  });
});
