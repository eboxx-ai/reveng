import {
  createPlistNumberCollector,
  type PlistNumberLiterals,
} from "../../domain/apple/plistNumbers.js";
import { hasBinaryPlistSignature } from "../../domain/apple/appleArchiveFormat.js";

/** Observe bounded binary number markers without changing primary decode acceptance. */
export const binaryPlistNumberLiterals = (
  bytes: Buffer,
): PlistNumberLiterals => {
  const output = createPlistNumberCollector();
  if (bytes.length < 40 || !hasBinaryPlistSignature(bytes))
    return output.result(true);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const trailer = bytes.length - 32;
  const offsetWidth = bytes[trailer + 6] ?? 0;
  if (![1, 2, 4, 8].includes(offsetWidth)) return output.result(true);
  const countRaw = view.getBigUint64(trailer + 8);
  const tableRaw = view.getBigUint64(trailer + 24);
  const safeMaximum = BigInt(Number.MAX_SAFE_INTEGER);
  if (countRaw === 0n || countRaw > safeMaximum || tableRaw > safeMaximum)
    return output.result(true);
  if (tableRaw < 8n || tableRaw >= BigInt(trailer)) return output.result(true);
  const offsetTable = Number(tableRaw);
  const capacity = Math.floor((trailer - offsetTable) / offsetWidth);
  if (countRaw > BigInt(capacity)) return output.result(true);
  const count = Number(countRaw);
  const unsigned = (offset: number): number | undefined => {
    if (offset < offsetTable || offset + offsetWidth > trailer)
      return undefined;
    if (offsetWidth === 1) return view.getUint8(offset);
    if (offsetWidth === 2) return view.getUint16(offset);
    if (offsetWidth === 4) return view.getUint32(offset);
    const value = view.getBigUint64(offset);
    return value > safeMaximum ? undefined : Number(value);
  };
  for (let index = 0; index < count; index += 1) {
    const offset = unsigned(offsetTable + index * offsetWidth);
    if (offset === undefined || offset < 8 || offset >= offsetTable)
      return output.result(true);
    const marker = bytes[offset] ?? 0;
    const type = marker >> 4;
    if (type !== 1 && type !== 2) continue;
    const width = 2 ** (marker & 0xf);
    if (offset + 1 + width > offsetTable) return output.result(true);
    if (type === 1 && width === 8)
      output.integer(view.getBigInt64(offset + 1).toString());
    else if (type === 1 && width > 4) return output.result(true);
    else if (type === 2 && width === 4)
      output.real(view.getFloat32(offset + 1));
    else if (type === 2 && width === 8)
      output.real(view.getFloat64(offset + 1));
    else if (type === 2) return output.result(true);
  }
  return output.result();
};
