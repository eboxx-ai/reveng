import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { build, buildBinary } from "plist";
import { expect } from "vitest";

import { keyedArchiveResultSchema } from "../../src/domain/apple/keyedArchive.js";
import { parseEvidence } from "../../src/domain/evidence.js";
import { connectLocalToolsMcp } from "../fixtures/localToolsMcp.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import { cliTest } from "../support/cli/cliFixture.js";

cliTest.for(["CLI", "stdio MCP"] as const)(
  "preserves real character data through %s",
  async (surface, { cli }) => {
    const root = await createTestTempDirectory("rea-real-character-data-");
    const fields = { plain: 1.25, mixed: 1.25, cdata: 1.25, exponent: -12.5 };
    const archive = (value: Record<string, number | string>) => ({
      $archiver: "NSKeyedArchiver",
      $version: 100000,
      $objects: ["$null", value],
      $top: { root: { CF$UID: 1 } },
    });
    const xml = build(
      archive({
        ...fields,
        mixed: "MIXED",
        cdata: "CDATA",
        exponent: "EXPONENT",
      }),
    )
      .replace("<string>MIXED</string>", "<real>1<![CDATA[.25]]></real>")
      .replace("<string>CDATA</string>", "<real><![CDATA[1.25]]></real>")
      .replace(
        "<string>EXPONENT</string>",
        "<real>-1<![CDATA[.25]]>e<![CDATA[1]]></real>",
      );
    const mcp = surface === "stdio MCP" ? await connectLocalToolsMcp() : null;
    for (const [name, bytes] of [
      ["xml", Buffer.from(xml)],
      ["binary", Buffer.from(buildBinary(archive(fields)))],
    ] as const) {
      const path = join(root, `${name}.plist`);
      await writeFile(path, bytes);
      let evidence: unknown;
      if (mcp === null) {
        const response = await cli.run({
          arguments: ["inspect-keyed-archive", path, "--json"],
          environment: { REA_LOG_LEVEL: "silent" },
        });
        expect(response.exitCode, response.stderr).toBe(0);
        evidence = response.json;
      } else {
        expect((await mcp.call("open_binary", { path })).isError).not.toBe(
          true,
        );
        const response = await mcp.call("inspect_keyed_archive", {});
        expect(response.isError, JSON.stringify(response.content)).not.toBe(
          true,
        );
        evidence = response.structuredContent;
        expect((await mcp.call("close_binary", {})).isError).not.toBe(true);
      }
      const result = keyedArchiveResultSchema.parse(
        parseEvidence(evidence).normalized_result,
      );
      expect(result.objects.find(({ id }) => id === 1)?.value).toEqual(fields);
      expect(result.archive_sha256).toBe(
        createHash("sha256").update(bytes).digest("hex"),
      );
      expect(result.references).toMatchObject([
        { source: null, path: ["root"], target: 1, status: "resolved" },
      ]);
      expect(result.truncated).toBe(false);
      expect(
        result.limitations.some((note) =>
          /non-finite|metadata.*completely observed/u.test(note),
        ),
      ).toBe(false);
      expect(await readFile(path)).toEqual(bytes);
    }
  },
);
