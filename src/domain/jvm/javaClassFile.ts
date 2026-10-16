/**
 * Dependency-free structural reader for JVM `.class` files (JVMS §4).
 *
 * Scope: frame the class file — magic, version, constant pool, access flags,
 * this/super class, interfaces, fields, methods, and each attribute's name plus
 * its raw `info` bytes. Interpretation of specific attributes (SourceFile,
 * LineNumberTable, LocalVariableTable, LocalVariableTypeTable,
 * SourceDebugExtension) is layered on top of this reader, not performed here.
 *
 * Every length-prefixed read is bounded against the buffer before allocation;
 * malformed or truncated input yields a tagged {@link JavaClassFileParseError}
 * via {@link Result}, never a thrown parse or an unchecked allocation.
 */
import { type Result, err, ok } from "../result.js";

/** Constant-pool tags consumed by this reader (JVMS Table 4.4-B). */
export const CONSTANT_TAG = {
  utf8: 1,
  integer: 3,
  float: 4,
  long: 5,
  double: 6,
  class: 7,
  string: 8,
  fieldref: 9,
  methodref: 10,
  interfaceMethodref: 11,
  nameAndType: 12,
  methodHandle: 15,
  methodType: 16,
  dynamic: 17,
  invokeDynamic: 18,
  module: 19,
  package: 20,
} as const;

/** A single constant-pool slot. Only fields later lookups need are retained; other tags stay opaque by tag. */
export type ConstantPoolEntry =
  | {
      readonly tag: 1;
      readonly kind: "utf8";
      /**
       * The validated modified-UTF8 bytes, a view over the input. Decoded only
       * when referenced, via {@link resolveConstantUtf8}: an unused 65,535-byte
       * constant costs no string at all.
       */
      readonly bytes: Uint8Array;
    }
  | { readonly tag: 7; readonly kind: "class"; readonly nameIndex: number }
  | {
      readonly tag: 12;
      readonly kind: "name-and-type";
      readonly nameIndex: number;
      readonly descriptorIndex: number;
    }
  | {
      readonly kind: "opaque";
      readonly tag: number;
    }
  /** The unusable second slot consumed by a long/double entry (JVMS §4.4.5). */
  | { readonly kind: "unusable" };

/** A raw attribute: its resolved name and the exact `info` byte range, left undecoded. */
export interface JavaAttribute {
  readonly nameIndex: number;
  /** Resolved Utf8 name, or `null` when `nameIndex` is not a Utf8 constant. */
  readonly name: string | null;
  /** View over the class-file buffer; not copied. */
  readonly info: Uint8Array;
}

/** A field or method member with its access flags, identity indices, and raw attributes. */
export interface JavaMember {
  readonly accessFlags: number;
  readonly nameIndex: number;
  readonly name: string | null;
  readonly descriptorIndex: number;
  readonly descriptor: string | null;
  readonly attributes: readonly JavaAttribute[];
}

/** A framed class file. Index 0 of `constantPool` is a placeholder; real entries are 1-based (JVMS §4.1). */
export interface JavaClassFile {
  readonly minorVersion: number;
  readonly majorVersion: number;
  readonly constantPool: readonly ConstantPoolEntry[];
  readonly accessFlags: number;
  readonly thisClassIndex: number;
  readonly superClassIndex: number;
  readonly interfaceIndices: readonly number[];
  readonly fields: readonly JavaMember[];
  readonly methods: readonly JavaMember[];
  readonly attributes: readonly JavaAttribute[];
}

/** Why framing failed. Offsets are byte positions into the supplied buffer. */
export type JavaClassFileParseError =
  | { readonly kind: "bad-magic"; readonly offset: number }
  | {
      readonly kind: "truncated";
      readonly offset: number;
      readonly need: number;
      readonly have: number;
    }
  | {
      readonly kind: "unsupported-constant-tag";
      readonly offset: number;
      readonly tag: number;
    }
  | { readonly kind: "invalid-utf8"; readonly offset: number }
  | {
      readonly kind: "budget-exceeded";
      readonly offset: number;
      readonly resource: "interfaces" | "fields" | "methods" | "attributes";
      readonly declared: number;
      readonly remaining: number;
    }
  | {
      /** More retained attributes than the caller's budget allows. */
      readonly kind: "retained-attribute-budget";
      readonly offset: number;
      readonly limit: number;
    };

/**
 * A count of attribute objects a caller is willing to materialise, shared and
 * decremented across every attribute list framed with it.
 */
export interface AttributeBudget {
  remaining: number;
  readonly limit: number;
}

export const attributeBudget = (limit: number): AttributeBudget => ({
  remaining: limit,
  limit,
});

const CLASS_FILE_MAGIC = 0xcafebabe;

/** Sequential, bounds-checked big-endian cursor over the class-file bytes. */
export class ByteCursor {
  offset = 0;
  constructor(private readonly bytes: Uint8Array) {}

  get remaining(): number {
    return this.bytes.length - this.offset;
  }

  private ensure(n: number): JavaClassFileParseError | null {
    if (this.remaining < n) {
      return {
        kind: "truncated",
        offset: this.offset,
        need: n,
        have: this.remaining,
      };
    }
    return null;
  }

  u1(): Result<number, JavaClassFileParseError> {
    const short = this.ensure(1);
    if (short) return err(short);
    const value = this.bytes[this.offset]!;
    this.offset += 1;
    return ok(value);
  }

  u2(): Result<number, JavaClassFileParseError> {
    const short = this.ensure(2);
    if (short) return err(short);
    const value =
      (this.bytes[this.offset]! << 8) | this.bytes[this.offset + 1]!;
    this.offset += 2;
    return ok(value);
  }

  u4(): Result<number, JavaClassFileParseError> {
    const short = this.ensure(4);
    if (short) return err(short);
    const value =
      this.bytes[this.offset]! * 0x1000000 +
      ((this.bytes[this.offset + 1]! << 16) |
        (this.bytes[this.offset + 2]! << 8) |
        this.bytes[this.offset + 3]!);
    this.offset += 4;
    return ok(value);
  }

  /** Advance past `n` already-bounds-checked bytes without creating a view. */
  skip(n: number): Result<void, JavaClassFileParseError> {
    const short = this.ensure(n);
    if (short) return err(short);
    this.offset += n;
    return ok(undefined);
  }

  /** Return a view over `n` bytes and advance; no copy. */
  slice(n: number): Result<Uint8Array, JavaClassFileParseError> {
    const short = this.ensure(n);
    if (short) return err(short);
    const view = this.bytes.subarray(this.offset, this.offset + n);
    this.offset += n;
    return ok(view);
  }
}

/**
 * Validate modified-UTF8 (JVMS §4.4.7) in place, allocating nothing. Returns
 * the number of UTF-16 code units it decodes to, or null when malformed.
 */
const modifiedUtf8Units = (bytes: Uint8Array): number | null => {
  const isContinuation = (byte: number | undefined): boolean =>
    byte !== undefined && (byte & 0xc0) === 0x80;
  let units = 0;
  let i = 0;
  while (i < bytes.length) {
    const a = bytes[i]!;
    if (a === 0 || a >= 0xf0) return null;
    if (a < 0x80) i += 1;
    else if (a < 0xe0) {
      // A 2-byte sequence leads with 110xxxxx (>= 0xc0); 0x80-0xbf are
      // continuation bytes and are never valid as a lead. (0xc0 0x80 remains
      // the modified-UTF8 encoding of U+0000 and stays accepted.)
      if (a < 0xc0 || !isContinuation(bytes[i + 1])) return null;
      // Shortest form only (JVMS §4.4.7): a 2-byte sequence encodes
      // U+0080..U+07FF, or U+0000 as exactly 0xC0 0x80. An overlong form
      // (e.g. 0xC0 0x81 for U+0001) is rejected, as the JVM rejects it.
      const unit = ((a & 0x1f) << 6) | (bytes[i + 1]! & 0x3f);
      if (unit < 0x80 && !(a === 0xc0 && bytes[i + 1] === 0x80)) return null;
      i += 2;
    } else {
      if (!isContinuation(bytes[i + 1]) || !isContinuation(bytes[i + 2]))
        return null;
      // Shortest form only: a 3-byte sequence encodes U+0800..U+FFFF.
      if (a === 0xe0 && bytes[i + 1]! < 0xa0) return null;
      i += 3;
    }
    units += 1;
  }
  return units;
};

const DECODE_CHUNK = 8192;

/**
 * Decode already-validated modified-UTF8 into one flat string. Code units are
 * written to a typed array and converted in bounded chunks: per-character
 * concatenation would build a rope of tens of thousands of nodes per string.
 * Lone surrogates are preserved exactly (a UTF-16 TextDecoder would replace
 * them).
 */
const decodeValidModifiedUtf8 = (bytes: Uint8Array, units: number): string => {
  const out = new Uint16Array(units);
  let u = 0;
  let i = 0;
  while (i < bytes.length) {
    const a = bytes[i]!;
    if (a < 0x80) {
      out[u] = a;
      i += 1;
    } else if (a < 0xe0) {
      out[u] = ((a & 0x1f) << 6) | (bytes[i + 1]! & 0x3f);
      i += 2;
    } else {
      out[u] =
        ((a & 0x0f) << 12) |
        ((bytes[i + 1]! & 0x3f) << 6) |
        (bytes[i + 2]! & 0x3f);
      i += 3;
    }
    u += 1;
  }
  let text = "";
  for (let at = 0; at < units; at += DECODE_CHUNK)
    text += String.fromCharCode(...out.subarray(at, at + DECODE_CHUNK));
  return text;
};

/** Fixed `info` byte sizes for constant tags whose body is not length-prefixed. */
const FIXED_CONSTANT_SIZE: Readonly<Record<number, number>> = {
  [CONSTANT_TAG.integer]: 4,
  [CONSTANT_TAG.float]: 4,
  [CONSTANT_TAG.long]: 8,
  [CONSTANT_TAG.double]: 8,
  [CONSTANT_TAG.class]: 2,
  [CONSTANT_TAG.string]: 2,
  [CONSTANT_TAG.fieldref]: 4,
  [CONSTANT_TAG.methodref]: 4,
  [CONSTANT_TAG.interfaceMethodref]: 4,
  [CONSTANT_TAG.nameAndType]: 4,
  [CONSTANT_TAG.methodHandle]: 3,
  [CONSTANT_TAG.methodType]: 2,
  [CONSTANT_TAG.dynamic]: 4,
  [CONSTANT_TAG.invokeDynamic]: 4,
  [CONSTANT_TAG.module]: 2,
  [CONSTANT_TAG.package]: 2,
};

/** Resolve a constant-pool index to its Utf8 string, or `null` when it is not a Utf8 entry. */
/** Decoded strings per pool, so each referenced constant is decoded once. */
const DECODED = new WeakMap<
  readonly ConstantPoolEntry[],
  Map<number, string>
>();

/** Resolve a CONSTANT_Utf8 index to its string, decoding it on first use. */
export const resolveConstantUtf8 = (
  pool: readonly ConstantPoolEntry[],
  index: number,
): string | null => {
  const entry = pool[index];
  if (entry === undefined || entry.kind !== "utf8") return null;
  let decoded = DECODED.get(pool);
  if (decoded === undefined) {
    decoded = new Map();
    DECODED.set(pool, decoded);
  }
  let text = decoded.get(index);
  if (text === undefined) {
    // Validated when the pool was parsed, so the unit count is non-null.
    text = decodeValidModifiedUtf8(
      entry.bytes,
      modifiedUtf8Units(entry.bytes) ?? 0,
    );
    decoded.set(index, text);
  }
  return text;
};

/**
 * Upper bound on the UTF-8 bytes `JSON.stringify` emits for a validated
 * modified-UTF8 constant (quotes included), computed from its bytes alone.
 * Sound because validation rejects overlong forms: a control character can
 * only arrive as one byte (or U+0000 as 0xC0 0x80), never packed into a
 * multi-byte sequence that is charged less than its escape.
 * control characters escape to `\\u00XX`, quote/backslash to two bytes, and a
 * 3-byte sequence is charged 6 in case it is a lone surrogate (`\\udXXX`).
 */
export const constantUtf8JsonBound = (
  pool: readonly ConstantPoolEntry[],
  index: number,
): number => {
  const entry = pool[index];
  if (entry === undefined || entry.kind !== "utf8") return 4; // null
  const bytes = entry.bytes;
  let total = 2;
  let i = 0;
  while (i < bytes.length) {
    const a = bytes[i]!;
    if (a < 0x80) {
      total += a < 0x20 ? 6 : a === 0x22 || a === 0x5c ? 2 : 1;
      i += 1;
    } else if (a < 0xe0) {
      // 0xC0 0x80 is U+0000, escaped as \u0000.
      total += a === 0xc0 && bytes[i + 1] === 0x80 ? 6 : 2;
      i += 2;
    } else {
      total += a === 0xed ? 6 : 3;
      i += 3;
    }
  }
  return total;
};

const parseConstantPool = (
  cursor: ByteCursor,
): Result<ConstantPoolEntry[], JavaClassFileParseError> => {
  const countResult = cursor.u2();
  if (!countResult.ok) return countResult;
  const count = countResult.value;
  // Constant pool is indexed 1..count-1; slot 0 is a reserved placeholder.
  const pool: ConstantPoolEntry[] = [{ kind: "opaque", tag: 0 }];
  for (let index = 1; index < count; index += 1) {
    const tagResult = cursor.u1();
    if (!tagResult.ok) return tagResult;
    const tag = tagResult.value;
    const tagOffset = cursor.offset - 1;
    if (tag === CONSTANT_TAG.utf8) {
      const lenResult = cursor.u2();
      if (!lenResult.ok) return lenResult;
      const bytesResult = cursor.slice(lenResult.value);
      if (!bytesResult.ok) return bytesResult;
      // Validate now (a malformed constant still rejects the class, as the
      // JVM would) but retain only the byte view; decode on first use.
      if (modifiedUtf8Units(bytesResult.value) === null)
        return err({ kind: "invalid-utf8", offset: tagOffset });
      pool.push({ tag: 1, kind: "utf8", bytes: bytesResult.value });
      continue;
    }
    if (tag === CONSTANT_TAG.class) {
      const nameIndex = cursor.u2();
      if (!nameIndex.ok) return nameIndex;
      pool.push({ tag: 7, kind: "class", nameIndex: nameIndex.value });
      continue;
    }
    if (tag === CONSTANT_TAG.nameAndType) {
      const nameIndex = cursor.u2();
      if (!nameIndex.ok) return nameIndex;
      const descriptorIndex = cursor.u2();
      if (!descriptorIndex.ok) return descriptorIndex;
      pool.push({
        tag: 12,
        kind: "name-and-type",
        nameIndex: nameIndex.value,
        descriptorIndex: descriptorIndex.value,
      });
      continue;
    }
    const fixed = FIXED_CONSTANT_SIZE[tag];
    if (fixed === undefined) {
      return err({ kind: "unsupported-constant-tag", offset: tagOffset, tag });
    }
    const skip = cursor.slice(fixed);
    if (!skip.ok) return skip;
    pool.push({ kind: "opaque", tag });
    // Long and Double occupy two pool slots; the next is unusable (JVMS §4.4.5).
    if (tag === CONSTANT_TAG.long || tag === CONSTANT_TAG.double) {
      pool.push({ kind: "unusable" });
      index += 1;
    }
  }
  return ok(pool);
};

/** Attributes framed before a failure, and the failure (if any) that stopped framing. */
export interface FramedAttributes {
  readonly attributes: readonly JavaAttribute[];
  readonly error: JavaClassFileParseError | null;
}

/**
 * Frame an `attributes_count`-prefixed attribute list from the cursor's
 * current position, keeping the successfully framed prefix when a later
 * attribute is malformed. Every attribute is framed and bounds-checked, but
 * only those named in `keep` are materialised (a crafted class can declare up
 * to 65,535 attributes per owner), and each retained one is charged to
 * `budget` so repeated wanted attributes cannot grow without bound either.
 */
export const frameAttributes = (
  cursor: ByteCursor,
  pool: readonly ConstantPoolEntry[],
  keep: ReadonlySet<string>,
  budget?: AttributeBudget,
): FramedAttributes => {
  const attributes: JavaAttribute[] = [];
  const stop = (error: JavaClassFileParseError): FramedAttributes => ({
    attributes,
    error,
  });
  const countResult = cursor.u2();
  if (!countResult.ok) return stop(countResult.error);
  for (let i = 0; i < countResult.value; i += 1) {
    const nameIndex = cursor.u2();
    if (!nameIndex.ok) return stop(nameIndex.error);
    const lengthResult = cursor.u4();
    if (!lengthResult.ok) return stop(lengthResult.error);
    if (lengthResult.value > cursor.remaining)
      return stop({
        kind: "budget-exceeded",
        offset: cursor.offset,
        resource: "attributes",
        declared: lengthResult.value,
        remaining: cursor.remaining,
      });
    const name = resolveConstantUtf8(pool, nameIndex.value);
    if (name === null || !keep.has(name)) {
      const skipped = cursor.skip(lengthResult.value);
      if (!skipped.ok) return stop(skipped.error);
      continue;
    }
    if (budget !== undefined) {
      if (budget.remaining <= 0)
        return stop({
          kind: "retained-attribute-budget",
          offset: cursor.offset,
          limit: budget.limit,
        });
      budget.remaining -= 1;
    }
    const info = cursor.slice(lengthResult.value);
    if (!info.ok) return stop(info.error);
    attributes.push({ nameIndex: nameIndex.value, name, info: info.value });
  }
  return { attributes, error: null };
};

/** {@link frameAttributes}, failing the whole list on any framing error. */
export const parseAttributes = (
  cursor: ByteCursor,
  pool: readonly ConstantPoolEntry[],
  keep: ReadonlySet<string>,
  budget?: AttributeBudget,
): Result<JavaAttribute[], JavaClassFileParseError> => {
  const framed = frameAttributes(cursor, pool, keep, budget);
  return framed.error === null ? ok([...framed.attributes]) : err(framed.error);
};

/** Attributes the debug-metadata reader consumes, per owner (JVMS §4.7). */
export const RETAINED_ATTRIBUTES = {
  field: new Set<string>(),
  method: new Set(["Code"]),
  class: new Set(["SourceFile", "SourceDebugExtension"]),
  code: new Set([
    "LineNumberTable",
    "LocalVariableTable",
    "LocalVariableTypeTable",
  ]),
} as const;

const parseMembers = (
  cursor: ByteCursor,
  pool: readonly ConstantPoolEntry[],
  resource: "fields" | "methods",
  budget: AttributeBudget | undefined,
): Result<JavaMember[], JavaClassFileParseError> => {
  const countResult = cursor.u2();
  if (!countResult.ok) return countResult;
  const count = countResult.value;
  // Each member is at least 8 bytes before its attributes; reject an impossible count up front.
  if (count * 8 > cursor.remaining) {
    return err({
      kind: "budget-exceeded",
      offset: cursor.offset,
      resource,
      declared: count,
      remaining: cursor.remaining,
    });
  }
  const members: JavaMember[] = [];
  for (let i = 0; i < count; i += 1) {
    const accessFlags = cursor.u2();
    if (!accessFlags.ok) return accessFlags;
    const nameIndex = cursor.u2();
    if (!nameIndex.ok) return nameIndex;
    const descriptorIndex = cursor.u2();
    if (!descriptorIndex.ok) return descriptorIndex;
    const attributes = parseAttributes(
      cursor,
      pool,
      resource === "fields"
        ? RETAINED_ATTRIBUTES.field
        : RETAINED_ATTRIBUTES.method,
      budget,
    );
    if (!attributes.ok) return attributes;
    members.push({
      accessFlags: accessFlags.value,
      nameIndex: nameIndex.value,
      name: resolveConstantUtf8(pool, nameIndex.value),
      descriptorIndex: descriptorIndex.value,
      descriptor: resolveConstantUtf8(pool, descriptorIndex.value),
      attributes: attributes.value,
    });
  }
  return ok(members);
};

/** Frame a `.class` file. The returned attribute `info` views share the input buffer. */
export const parseJavaClassFile = (
  bytes: Uint8Array,
  options: { readonly retainedAttributeBudget?: number } = {},
): Result<JavaClassFile, JavaClassFileParseError> => {
  const budget =
    options.retainedAttributeBudget === undefined
      ? undefined
      : attributeBudget(options.retainedAttributeBudget);
  const cursor = new ByteCursor(bytes);

  const magic = cursor.u4();
  if (!magic.ok) return magic;
  if (magic.value !== CLASS_FILE_MAGIC) {
    return err({ kind: "bad-magic", offset: 0 });
  }

  const minorVersion = cursor.u2();
  if (!minorVersion.ok) return minorVersion;
  const majorVersion = cursor.u2();
  if (!majorVersion.ok) return majorVersion;

  const pool = parseConstantPool(cursor);
  if (!pool.ok) return pool;

  const accessFlags = cursor.u2();
  if (!accessFlags.ok) return accessFlags;
  const thisClassIndex = cursor.u2();
  if (!thisClassIndex.ok) return thisClassIndex;
  const superClassIndex = cursor.u2();
  if (!superClassIndex.ok) return superClassIndex;

  const interfaceCount = cursor.u2();
  if (!interfaceCount.ok) return interfaceCount;
  if (interfaceCount.value * 2 > cursor.remaining) {
    return err({
      kind: "budget-exceeded",
      offset: cursor.offset,
      resource: "interfaces",
      declared: interfaceCount.value,
      remaining: cursor.remaining,
    });
  }
  const interfaceIndices: number[] = [];
  for (let i = 0; i < interfaceCount.value; i += 1) {
    const ref = cursor.u2();
    if (!ref.ok) return ref;
    interfaceIndices.push(ref.value);
  }

  const fields = parseMembers(cursor, pool.value, "fields", budget);
  if (!fields.ok) return fields;
  const methods = parseMembers(cursor, pool.value, "methods", budget);
  if (!methods.ok) return methods;
  const attributes = parseAttributes(
    cursor,
    pool.value,
    RETAINED_ATTRIBUTES.class,
    budget,
  );
  if (!attributes.ok) return attributes;

  return ok({
    minorVersion: minorVersion.value,
    majorVersion: majorVersion.value,
    constantPool: pool.value,
    accessFlags: accessFlags.value,
    thisClassIndex: thisClassIndex.value,
    superClassIndex: superClassIndex.value,
    interfaceIndices,
    fields: fields.value,
    methods: methods.value,
    attributes: attributes.value,
  });
};
