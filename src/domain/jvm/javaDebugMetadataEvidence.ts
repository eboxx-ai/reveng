/**
 * Normalize decoded JVM debug metadata into a deterministic, report-ready shape
 * with examined coverage. This owns ordering and the coverage tally so CLI and
 * MCP adapters present identical facts; it adds no interpretation beyond
 * {@link decodeClassDebugMetadata}.
 */
import type {
  ClassDebugMetadata,
  MethodDebugMetadata,
  MethodDebugState,
} from "./javaDebugMetadata.js";

/** Count of methods in each debug state; completeness is derived from examined methods, not prose. */
export interface MethodDebugCoverage {
  readonly total: number;
  readonly present: number;
  readonly partial: number;
  readonly stripped: number;
  readonly malformed: number;
  readonly notApplicable: number;
}

export interface JavaDebugMetadataEvidence {
  readonly sourceFile: ClassDebugMetadata["sourceFile"];
  readonly sourceDebugExtension: ClassDebugMetadata["sourceDebugExtension"];
  /** Methods ordered deterministically by name then descriptor; unnamed entries sort last. */
  readonly methods: readonly MethodDebugMetadata[];
  readonly coverage: MethodDebugCoverage;
}

const STATE_COUNTER: Readonly<
  Record<MethodDebugState, keyof Omit<MethodDebugCoverage, "total">>
> = {
  present: "present",
  partial: "partial",
  stripped: "stripped",
  malformed: "malformed",
  "not-applicable": "notApplicable",
};

const compareNullableString = (a: string | null, b: string | null): number => {
  // null (unresolved identity) sorts after any resolved name, deterministically.
  if (a === b) return 0;
  if (a === null) return 1;
  if (b === null) return -1;
  return a < b ? -1 : 1;
};

const orderMethods = (
  methods: readonly MethodDebugMetadata[],
): readonly MethodDebugMetadata[] =>
  [...methods].sort(
    (a, b) =>
      compareNullableString(a.name, b.name) ||
      compareNullableString(a.descriptor, b.descriptor),
  );

const tallyCoverage = (
  methods: readonly MethodDebugMetadata[],
): MethodDebugCoverage => {
  const coverage = {
    total: methods.length,
    present: 0,
    partial: 0,
    stripped: 0,
    malformed: 0,
    notApplicable: 0,
  };
  for (const method of methods) coverage[STATE_COUNTER[method.state]] += 1;
  return coverage;
};

/** Build the normalized, deterministically ordered Evidence for one class. */
export const buildJavaDebugMetadataEvidence = (
  metadata: ClassDebugMetadata,
): JavaDebugMetadataEvidence => {
  const methods = orderMethods(metadata.methods);
  return {
    sourceFile: metadata.sourceFile,
    sourceDebugExtension: metadata.sourceDebugExtension,
    methods,
    coverage: tallyCoverage(methods),
  };
};
