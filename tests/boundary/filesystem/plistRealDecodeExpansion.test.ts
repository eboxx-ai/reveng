import { DOMParser } from "@xmldom/xmldom";
import { expect, it, vi } from "vitest";

import { decodeKeyedArchiveBytes } from "../../../src/artifacts/apple/KeyedArchiveReader.js";

it.each([
  {
    body: `1<![CDATA[${"&".repeat(256 * 1024)}]]>`,
    expected: 1,
    name: "entity-like text",
  },
  { body: "<![CDATA[1e20]]>", expected: 1e20, name: "a compact exponent" },
])("does not expand $name before value decoding", ({ body, expected }) => {
  const bytes = Buffer.from(
    `<plist><dict><key>$archiver</key><string>NSKeyedArchiver</string><key>$version</key><integer>100000</integer><key>$objects</key><array><string>$null</string><dict><key>value</key><real>${body}</real></dict></array><key>$top</key><dict><key>root</key><dict><key>CF$UID</key><integer>1</integer></dict></dict></dict></plist>`,
  );
  const original = DOMParser.prototype.parseFromString;
  const parseSizes: number[] = [];
  const parser = vi
    .spyOn(DOMParser.prototype, "parseFromString")
    .mockImplementation(function (this: DOMParser, ...args) {
      parseSizes.push(Buffer.byteLength(args[0]));
      return original.call(this, ...args);
    });
  try {
    const result = decodeKeyedArchiveBytes(bytes, { offset: 0, limit: 20 });
    expect(result.objects[1]?.value).toEqual({ value: expected });
    // Observe the real preflight and value decoder, rather than a mock parser.
    expect(parseSizes).toHaveLength(2);
    expect(Math.max(...parseSizes)).toBeLessThanOrEqual(bytes.length);
  } finally {
    parser.mockRestore();
  }
});
