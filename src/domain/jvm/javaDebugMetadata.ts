/**
 * Decode the compiler-emitted debug attributes relevant to debugging readiness
 * (JVMS §4.7.10–4.7.14) from a framed {@link JavaClassFile}:
 * `SourceFile`, `SourceDebugExtension`, `LineNumberTable`, `LocalVariableTable`
 * and `LocalVariableTypeTable`.
 *
 * This module interprets attribute `info` bytes that {@link parseJavaClassFile}
 * framed but left undecoded. It never executes Java, resolves source URLs, or
 * claims that any source matches a declared `SourceFile`. `SourceDebugExtension`
 * stays opaque — only its presence and size are reported. Facts are preserved
 * on partial failure: a table that runs short is reported `malformed` with the
 * entries recovered before the short read, not discarded.
 */
import {
  ByteCursor,
  type ConstantPoolEntry,
  type JavaClassFile,
  type JavaMember,
  attributeBudget,
  constantUtf8JsonBound,
  frameAttributes,
  RETAINED_ATTRIBUTES,
  resolveConstantUtf8,
} from "./javaClassFile.js";

/** Whether a named attribute was found and whether it decoded cleanly. */
/**
 * `unread` means the table could not be looked for: an earlier sibling
 * attribute in the same `Code` attribute was malformed, so framing stopped
 * before reaching it. It is unknown, never `absent`.
 */
export type AttributePresence = "absent" | "present" | "malformed" | "unread";

/** A decoded debug table with the entries recovered and how fully it was read. */
export interface DebugTable<T> {
  readonly presence: AttributePresence;
  /** The attribute's self-declared entry count, or 0 when the attribute is absent. */
  readonly declaredCount: number;
  readonly entries: readonly T[];
}

export interface LineNumberEntry {
  readonly startPc: number;
  readonly lineNumber: number;
}

export interface LocalVariableEntry {
  readonly startPc: number;
  readonly length: number;
  readonly nameIndex: number;
  readonly name: string | null;
  readonly descriptorIndex: number;
  readonly descriptor: string | null;
  /** The local-variable array slot; wide (long/double) locals occupy this slot and the next. */
  readonly slot: number;
  /** The scope `[startPc, startPc+length)` lies outside the method's code length. */
  readonly outOfRange: boolean;
}

export interface LocalVariableTypeEntry {
  readonly startPc: number;
  readonly length: number;
  readonly nameIndex: number;
  readonly name: string | null;
  readonly signatureIndex: number;
  readonly signature: string | null;
  readonly slot: number;
  /** The scope `[startPc, startPc+length)` lies outside the method's code length. */
  readonly outOfRange: boolean;
}

/** Overall debugging-readiness of one method's body. */
export type MethodDebugState =
  | "present" // line and local-variable tables both decoded
  | "partial" // one of them present, the other absent
  | "stripped" // a body exists but carries neither table (e.g. javac -g:none)
  | "malformed" // a present table failed to decode fully
  | "not-applicable"; // no Code attribute (native/abstract, or no body)

export interface MethodDebugMetadata {
  readonly name: string | null;
  readonly descriptor: string | null;
  readonly state: MethodDebugState;
  readonly hasCode: boolean;
  readonly lineNumbers: DebugTable<LineNumberEntry>;
  readonly localVariables: DebugTable<LocalVariableEntry>;
  readonly localVariableTypes: DebugTable<LocalVariableTypeEntry>;
  /**
   * Slots that appear in more than one `LocalVariableTable` entry. Reuse is
   * legal and does not imply error, but a reused slot may denote different
   * variables across disjoint scope ranges, so it is surfaced, not collapsed.
   */
  readonly reusedSlots: readonly number[];
}

export interface ClassDebugMetadata {
  readonly sourceFile: {
    readonly presence: Exclude<AttributePresence, "unread">;
    readonly name: string | null;
  };
  readonly sourceDebugExtension: {
    readonly presence: Exclude<AttributePresence, "unread">;
    /** Byte length of the opaque extension; the bytes themselves are never interpreted here. */
    readonly byteLength: number;
  };
  readonly methods: readonly MethodDebugMetadata[];
}

type NamedAttribute = {
  readonly name: string | null;
  readonly info: Uint8Array;
};

/** First matching attribute's info. For names JVMS permits at most once (Code, SourceFile, SourceDebugExtension). */
const findAttribute = (
  attributes: readonly NamedAttribute[],
  name: string,
): Uint8Array | null => attributes.find((a) => a.name === name)?.info ?? null;

/**
 * Every matching attribute's info, in order. JVMS §4.7.12–14 permit multiple
 * LineNumberTable / LocalVariableTable / LocalVariableTypeTable attributes in
 * one Code attribute; the full table is their union.
 */
const collectAttributes = (
  attributes: readonly NamedAttribute[],
  name: string,
): readonly Uint8Array[] =>
  attributes.filter((a) => a.name === name).map((a) => a.info);

/**
 * Decode a fixed-stride table, merging every occurrence of a repeatable
 * attribute into one table. Reads up to each occurrence's self-declared count,
 * stopping early if its buffer runs short; a short read or trailing bytes mark
 * the whole table `malformed` while keeping every entry decoded before it.
 */
const decodeTable = <T>(
  infos: readonly Uint8Array[],
  stride: number,
  decodeEntry: (cursor: ByteCursor) => T,
): DebugTable<T> => {
  if (infos.length === 0)
    return { presence: "absent", declaredCount: 0, entries: [] };
  const entries: T[] = [];
  let declaredCount = 0;
  let malformed = false;
  for (const info of infos) {
    const cursor = new ByteCursor(info);
    const countResult = cursor.u2();
    if (!countResult.ok) {
      malformed = true;
      continue;
    }
    declaredCount += countResult.value;
    let short = false;
    for (let i = 0; i < countResult.value; i += 1) {
      if (cursor.remaining < stride) {
        short = true;
        break;
      }
      entries.push(decodeEntry(cursor));
    }
    // A short read, or trailing bytes past the declared entries, is malformed
    // rather than silently ignored (JVMS fixes attribute_length exactly).
    if (short || cursor.remaining !== 0) malformed = true;
  }
  return {
    presence: malformed ? "malformed" : "present",
    declaredCount,
    entries,
  };
};

const u2 = (cursor: ByteCursor): number => {
  const result = cursor.u2();
  // Guarded by the `remaining >= stride` check in decodeTable before each entry.
  return result.ok ? result.value : 0;
};

const decodeLineNumberTable = (
  infos: readonly Uint8Array[],
): DebugTable<LineNumberEntry> =>
  decodeTable(infos, 4, (cursor) => ({
    startPc: u2(cursor),
    lineNumber: u2(cursor),
  }));

/** A scope lies outside the code when it starts at/after the end or extends past it. */
const scopeOutOfRange = (
  startPc: number,
  length: number,
  codeLength: number,
): boolean => startPc >= codeLength || startPc + length > codeLength;

const decodeLocalVariableTable = (
  infos: readonly Uint8Array[],
  pool: readonly ConstantPoolEntry[],
  codeLength: number,
): DebugTable<LocalVariableEntry> =>
  decodeTable(infos, 10, (cursor) => {
    const startPc = u2(cursor);
    const length = u2(cursor);
    const nameIndex = u2(cursor);
    const descriptorIndex = u2(cursor);
    const slot = u2(cursor);
    return {
      startPc,
      length,
      nameIndex,
      name: resolveConstantUtf8(pool, nameIndex),
      descriptorIndex,
      descriptor: resolveConstantUtf8(pool, descriptorIndex),
      slot,
      outOfRange: scopeOutOfRange(startPc, length, codeLength),
    };
  });

const decodeLocalVariableTypeTable = (
  infos: readonly Uint8Array[],
  pool: readonly ConstantPoolEntry[],
  codeLength: number,
): DebugTable<LocalVariableTypeEntry> =>
  decodeTable(infos, 10, (cursor) => {
    const startPc = u2(cursor);
    const length = u2(cursor);
    const nameIndex = u2(cursor);
    const signatureIndex = u2(cursor);
    const slot = u2(cursor);
    return {
      startPc,
      length,
      nameIndex,
      name: resolveConstantUtf8(pool, nameIndex),
      signatureIndex,
      signature: resolveConstantUtf8(pool, signatureIndex),
      slot,
      outOfRange: scopeOutOfRange(startPc, length, codeLength),
    };
  });

/** Advance past the fixed Code header and exception table to its sub-attributes, keeping code_length. */
const seekCodeSubAttributes = (
  code: Uint8Array,
): { readonly cursor: ByteCursor; readonly codeLength: number } | null => {
  const cursor = new ByteCursor(code);
  if (!cursor.u2().ok) return null; // max_stack
  if (!cursor.u2().ok) return null; // max_locals
  const codeLength = cursor.u4();
  if (!codeLength.ok || !cursor.slice(codeLength.value).ok) return null;
  const exceptionTableLength = cursor.u2();
  if (
    !exceptionTableLength.ok ||
    !cursor.slice(exceptionTableLength.value * 8).ok
  )
    return null;
  return { cursor, codeLength: codeLength.value };
};

const computeReusedSlots = (
  entries: readonly LocalVariableEntry[],
): number[] => {
  const counts = new Map<number, number>();
  for (const entry of entries)
    counts.set(entry.slot, (counts.get(entry.slot) ?? 0) + 1);
  return [...counts.entries()]
    .filter(([, count]) => count > 1)
    .map(([slot]) => slot)
    .sort((a, b) => a - b);
};

const classifyMethod = (
  hasCode: boolean,
  lineNumbers: DebugTable<LineNumberEntry>,
  localVariables: DebugTable<LocalVariableEntry>,
  localVariableTypes: DebugTable<LocalVariableTypeEntry>,
): MethodDebugState => {
  if (!hasCode) return "not-applicable";
  if (
    lineNumbers.presence === "malformed" ||
    localVariables.presence === "malformed" ||
    localVariableTypes.presence === "malformed"
  ) {
    return "malformed";
  }
  const hasLine = lineNumbers.presence === "present";
  const hasLocals = localVariables.presence === "present";
  if (hasLine && hasLocals) return "present";
  if (!hasLine && !hasLocals) return "stripped";
  return "partial";
};

/** Decode one method's debug tables from its `Code` attribute, if any. */
export const decodeMethodDebugMetadata = (
  method: JavaMember,
  pool: readonly ConstantPoolEntry[],
): MethodDebugMetadata => {
  const code = findAttribute(method.attributes, "Code");
  const absentTable = <T>(): DebugTable<T> => ({
    presence: "absent",
    declaredCount: 0,
    entries: [],
  });
  if (code === null) {
    return {
      name: method.name,
      descriptor: method.descriptor,
      state: "not-applicable",
      hasCode: false,
      lineNumbers: absentTable(),
      localVariables: absentTable(),
      localVariableTypes: absentTable(),
      reusedSlots: [],
    };
  }

  const seeked = seekCodeSubAttributes(code);
  // Keep every table framed before a malformed sibling; tables framing never
  // reached are `unread`, not `absent`.
  const framed = seeked
    ? frameAttributes(seeked.cursor, pool, RETAINED_ATTRIBUTES.code)
    : null;
  const attributes = framed?.attributes ?? [];
  const codeMalformed = seeked === null || (framed?.error ?? null) !== null;
  const codeLength = seeked?.codeLength ?? 0;
  const orUnread = <T>(table: DebugTable<T>): DebugTable<T> =>
    codeMalformed && table.presence === "absent"
      ? { ...table, presence: "unread" }
      : table;

  const lineNumbers = orUnread(
    decodeLineNumberTable(collectAttributes(attributes, "LineNumberTable")),
  );
  const localVariables = orUnread(
    decodeLocalVariableTable(
      collectAttributes(attributes, "LocalVariableTable"),
      pool,
      codeLength,
    ),
  );
  const localVariableTypes = orUnread(
    decodeLocalVariableTypeTable(
      collectAttributes(attributes, "LocalVariableTypeTable"),
      pool,
      codeLength,
    ),
  );

  const state = codeMalformed
    ? "malformed"
    : classifyMethod(true, lineNumbers, localVariables, localVariableTypes);

  return {
    name: method.name,
    descriptor: method.descriptor,
    state,
    hasCode: true,
    lineNumbers,
    localVariables,
    localVariableTypes,
    reusedSlots: computeReusedSlots(localVariables.entries),
  };
};

/** Fixed byte strides of the repeatable debug tables (JVMS §4.7.12–14). */
const DEBUG_TABLE_STRIDES: ReadonlyArray<readonly [string, number]> = [
  ["LineNumberTable", 4],
  ["LocalVariableTable", 10],
  ["LocalVariableTypeTable", 10],
];

/** Serialized overhead per projected object (keys, numbers, punctuation). */
const METHOD_OVERHEAD = 320;
const LINE_ENTRY_OVERHEAD = 48;
const LOCAL_ENTRY_OVERHEAD = 160;

/** What {@link decodeClassDebugMetadata} would materialise, projected without materialising it. */
export interface DebugOutputProjection {
  /** Projected objects: one per method plus every debug-table entry. */
  readonly entries: number;
  /** Estimated serialized bytes, counting every repeated constant-pool string. */
  readonly encodedBytes: number;
  /** Set when framing the debug tables exceeded the retained-attribute budget. */
  readonly attributeBudgetExceeded: boolean;
}

/**
 * Project the size of the debug-metadata report before building it. Reads each
 * table's `count` prefix and its constant-pool indices in place — no entry
 * objects — and charges every reference with the JSON-encoded length of the
 * string it names, so a name shared by thousands of entries is counted
 * thousands of times (`JSON.stringify` would expand it that many times).
 * String sizes are upper bounds computed once per constant from its bytes,
 * without decoding, and the walk stops once `stopAbove` is exceeded.
 * Code sub-attributes are framed against `attributeLimit`.
 */
export const projectDebugOutput = (
  cls: JavaClassFile,
  attributeLimit: number,
  stopAbove: { readonly entries: number; readonly encodedBytes: number } = {
    entries: Number.POSITIVE_INFINITY,
    encodedBytes: Number.POSITIVE_INFINITY,
  },
): DebugOutputProjection => {
  // Bounded from the bytes, never decoded: a refused class decodes nothing.
  // Each constant's bound is computed once; a name shared by millions of rows
  // is scanned once, not once per row.
  const bounds = new Map<number, number>();
  const stringBytes = (index: number): number => {
    let bound = bounds.get(index);
    if (bound === undefined) {
      bound = constantUtf8JsonBound(cls.constantPool, index);
      bounds.set(index, bound);
    }
    return bound;
  };
  const budget = attributeBudget(attributeLimit);
  let entries = cls.methods.length;
  let encodedBytes = 4096;
  // Stop as soon as either running total passes the caller's limit: the
  // answer is already "refuse", and finishing the walk is wasted work.
  const over = (): boolean =>
    entries > stopAbove.entries || encodedBytes > stopAbove.encodedBytes;
  for (const method of cls.methods) {
    if (over()) break;
    encodedBytes +=
      METHOD_OVERHEAD +
      stringBytes(method.nameIndex) +
      stringBytes(method.descriptorIndex);
    const code = findAttribute(method.attributes, "Code");
    if (code === null) continue;
    const seeked = seekCodeSubAttributes(code);
    if (seeked === null) continue;
    const framed = frameAttributes(
      seeked.cursor,
      cls.constantPool,
      RETAINED_ATTRIBUTES.code,
      budget,
    );
    if (framed.error?.kind === "retained-attribute-budget")
      return { entries, encodedBytes, attributeBudgetExceeded: true };
    for (const [name, stride] of DEBUG_TABLE_STRIDES)
      for (const info of collectAttributes(framed.attributes, name)) {
        if (info.length < 2) continue;
        const declared = (info[0]! << 8) | info[1]!;
        const count = Math.min(
          declared,
          Math.floor((info.length - 2) / stride),
        );
        entries += count;
        if (stride === 4) {
          encodedBytes += count * LINE_ENTRY_OVERHEAD;
          continue;
        }
        // name_index and descriptor/signature_index sit at +4 and +6.
        for (let i = 0; i < count && !over(); i += 1) {
          const at = 2 + i * stride;
          encodedBytes +=
            LOCAL_ENTRY_OVERHEAD +
            stringBytes((info[at + 4]! << 8) | info[at + 5]!) +
            stringBytes((info[at + 6]! << 8) | info[at + 7]!);
        }
      }
  }
  return { entries, encodedBytes, attributeBudgetExceeded: false };
};

/** Decode class-level debug attributes and every method's debug tables. */
export const decodeClassDebugMetadata = (
  cls: JavaClassFile,
): ClassDebugMetadata => {
  const sourceFileInfo = findAttribute(cls.attributes, "SourceFile");
  let sourceFile: ClassDebugMetadata["sourceFile"] = {
    presence: "absent",
    name: null,
  };
  if (sourceFileInfo !== null) {
    const cursor = new ByteCursor(sourceFileInfo);
    const indexResult = cursor.u2();
    // SourceFile_attribute is a single u2 index (JVMS §4.7.10): a length other
    // than exactly 2 bytes is malformed, not a usable name.
    sourceFile =
      indexResult.ok && sourceFileInfo.length === 2
        ? {
            presence: "present",
            name: resolveConstantUtf8(cls.constantPool, indexResult.value),
          }
        : { presence: "malformed", name: null };
  }

  const sdeInfo = findAttribute(cls.attributes, "SourceDebugExtension");
  const sourceDebugExtension: ClassDebugMetadata["sourceDebugExtension"] =
    sdeInfo === null
      ? { presence: "absent", byteLength: 0 }
      : { presence: "present", byteLength: sdeInfo.length };

  return {
    sourceFile,
    sourceDebugExtension,
    methods: cls.methods.map((method) =>
      decodeMethodDebugMetadata(method, cls.constantPool),
    ),
  };
};
