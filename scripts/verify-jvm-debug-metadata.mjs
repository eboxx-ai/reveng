#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { Ajv2020 } from "ajv/dist/2020.js";
import { parseEvidence } from "../dist/domain/evidence.js";
import {
  mcpTextValue,
  requireMcpToolError,
} from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

const execute = promisify(execFile);
const environment = Object.fromEntries(
  Object.entries(process.env).filter(([, value]) => typeof value === "string"),
);
const sha256 = (value) => createHash("sha256").update(value).digest("hex");

const probeTool = async (candidate) => {
  // javac/javap/java accept -version; jar only accepts --version.
  for (const flag of ["-version", "--version"]) {
    try {
      await execute(candidate, [flag]);
      return true;
    } catch {
      /* try the next flag */
    }
  }
  return false;
};

const resolveJdkTool = async (tool) => {
  const home = environment.JAVA_HOME;
  if (home !== undefined && isAbsolute(home)) {
    const candidate = join(home, "bin", tool);
    if (await probeTool(candidate)) return candidate;
  }
  return (await probeTool(tool)) ? tool : undefined;
};

const javac = await resolveJdkTool("javac");
const javap = await resolveJdkTool("javap");
const jarTool = await resolveJdkTool("jar");
if (javac === undefined || javap === undefined) {
  if (process.argv.includes("--require-tools"))
    throw new Error(
      "JVM real lane requires a JDK (javac + javap) on JAVA_HOME or PATH.",
    );
  console.log(
    JSON.stringify({
      status: "skipped",
      reason: "JVM real lane requires a JDK (javac + javap); none found.",
    }),
  );
  process.exit(0);
}

const entrypoint =
  process.argv.slice(2).find((arg) => !arg.startsWith("--")) ??
  fileURLToPath(new URL("./rea.mjs", import.meta.url));

/** Independent oracle: what the JDK's own reader reports for the class. */
const javapFacts = async (classPath) => {
  const { stdout } = await execute(
    javap,
    [
      "-v",
      "-p",
      "-l",
      "-classpath",
      dirname(classPath),
      classNameOf(classPath),
    ],
    { env: environment, timeout: 60_000, maxBuffer: 32 * 1024 * 1024 },
  );
  return {
    lineEntries: (stdout.match(/^\s*line \d+: \d+$/gm) ?? []).length,
    localTables: (stdout.match(/^\s*LocalVariableTable:$/gm) ?? []).length,
    localTypeTables: (stdout.match(/^\s*LocalVariableTypeTable:$/gm) ?? [])
      .length,
    descriptors: new Set(
      (stdout.match(/^\s*descriptor: (.+)$/gm) ?? []).map((line) =>
        line.replace(/^\s*descriptor: /, ""),
      ),
    ),
    sourceFile: stdout.match(/^\s*SourceFile: "(.+)"$/m)?.[1] ?? null,
  };
};
const classNameOf = (classPath) =>
  classPath.replace(/.*\//, "").replace(/\.class$/, "");

const inspectCli = async (path, extra = {}) => {
  const args = [entrypoint, "inspect-jvm-debug-metadata", path];
  if (extra.entry !== undefined) args.push("--entry", extra.entry);
  if (extra.release !== undefined)
    args.push("--release", String(extra.release));
  args.push("--format", "json");
  try {
    return JSON.parse(
      (
        await execute(process.execPath, args, {
          env: environment,
          timeout: 120_000,
          maxBuffer: 64 * 1024 * 1024,
        })
      ).stdout,
    );
  } catch (cause) {
    if (typeof cause.code === "number" && typeof cause.stdout === "string")
      return JSON.parse(cause.stdout);
    throw cause;
  }
};

const run = createVerifierRun();
const workspace = await mkdtemp(join(tmpdir(), "rea-jvm-verifier-"));
const client = new Client({
  name: "jvm-debug-metadata-verifier",
  version: "1",
});
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env: environment,
  stderr: "pipe",
});
let cases = 0;
const failures = [];

try {
  await client.connect(transport);
  const advertised = (await client.listTools()).tools.find(
    ({ name }) => name === "inspect_jvm_debug_metadata",
  );
  assert.ok(
    advertised?.outputSchema,
    "JVM tool must advertise an output schema",
  );
  const ajv = new Ajv2020({ strict: false, validateFormats: false });
  assert.ok(ajv.validateSchema(advertised.inputSchema), "input schema invalid");
  assert.ok(
    ajv.validateSchema(advertised.outputSchema),
    "output schema invalid",
  );

  const inspectMcp = async (path, extra = {}) => {
    const reply = await client.callTool({
      name: "inspect_jvm_debug_metadata",
      arguments: { path, ...extra },
    });
    return reply;
  };

  /** CLI and MCP must agree, the output must validate, and javap must confirm. */
  const inspectBoth = async (path, extra = {}) => {
    const cliValue = await inspectCli(path, extra);
    assert.equal(cliValue.category, undefined, JSON.stringify(cliValue));
    const cli = parseEvidence(cliValue);
    const reply = await inspectMcp(path, extra);
    assert.notEqual(reply.isError, true, mcpTextValue(reply));
    assert.ok(
      ajv.validate(advertised.outputSchema, reply.structuredContent),
      JSON.stringify(ajv.errors),
    );
    const mcp = parseEvidence(reply.structuredContent);
    assert.equal(
      cli.evidence_id,
      mcp.evidence_id,
      "CLI and MCP evidence differ",
    );
    assert.deepEqual(cli, mcp);
    cases += 2;
    return mcp.normalized_result;
  };

  const source = `import java.util.*;
class Debuggable<T> {
  int compute(int a, long b) { int x = a + 1; for (int i = 0; i < a; i++) { x += i; } return x; }
  int compute(int a) { return a; }
  <E> List<E> wrap(E e) { List<E> list = new ArrayList<>(); list.add(e); return list; }
  double mix(double d, long l) { double r = d + (double) l; return r; }
}
`;
  const src = join(workspace, "Debuggable.java");
  await writeFile(src, source);
  const gDir = join(workspace, "g");
  const noneDir = join(workspace, "none");
  await mkdir(gDir);
  await mkdir(noneDir);
  await execute(javac, ["-g", "-d", gDir, src], { env: environment });
  await execute(javac, ["-g:none", "-d", noneDir, src], { env: environment });

  const gClass = join(gDir, "Debuggable.class");
  const original = await readFile(gClass);
  const report = await inspectBoth(gClass);
  const oracle = await javapFacts(gClass);

  // Exact byte identity and class identity.
  assert.equal(report.artifact.sha256, sha256(original));
  assert.equal(report.artifact.bytes, original.length);
  assert.equal(report.class.internal_name, "Debuggable");
  assert.equal(report.runtime_execution, "not-performed");

  // Every decoded fact confirmed by javap, the JDK's own reader.
  assert.equal(
    report.source_file.name,
    oracle.sourceFile,
    "SourceFile mismatch",
  );
  const myLineEntries = report.methods.reduce(
    (total, m) => total + m.line_number_table.entries.length,
    0,
  );
  assert.equal(
    myLineEntries,
    oracle.lineEntries,
    "LineNumberTable entry count != javap",
  );
  const myLocalTables = report.methods.filter(
    (m) => m.local_variable_table.presence === "present",
  ).length;
  assert.equal(
    myLocalTables,
    oracle.localTables,
    "LocalVariableTable count != javap",
  );
  const myLocalTypeTables = report.methods.filter(
    (m) => m.local_variable_type_table.presence === "present",
  ).length;
  assert.equal(
    myLocalTypeTables,
    oracle.localTypeTables,
    "LocalVariableTypeTable count != javap",
  );
  assert.ok(
    myLocalTypeTables >= 1,
    "generic method must yield a LocalVariableTypeTable",
  );
  for (const m of report.methods)
    assert.ok(
      oracle.descriptors.has(m.descriptor),
      `descriptor ${m.descriptor} not reported by javap`,
    );
  // Overloaded compute: two methods, each present and named.
  const computes = report.methods.filter((m) => m.name === "compute");
  assert.equal(computes.length, 2, "both compute overloads must appear");
  assert.deepEqual(
    [...new Set(computes.map((m) => m.descriptor))].sort(),
    ["(I)I", "(IJ)I"],
    "overload descriptors",
  );
  for (const m of computes) assert.equal(m.state, "present");
  // Wide locals: mix(double,long) carries long/double params.
  const mix = report.methods.find((m) => m.name === "mix");
  assert.equal(mix?.descriptor, "(DJ)D");
  assert.ok(
    mix.local_variable_table.entries.some((e) => e.name === "d"),
    "named local 'd' expected",
  );

  // -g:none: stripped, no source file.
  const strippedReport = await inspectBoth(join(noneDir, "Debuggable.class"));
  assert.equal(strippedReport.source_file.presence, "absent");
  assert.ok(
    strippedReport.methods.every((m) => m.state === "stripped"),
    "all methods stripped under -g:none",
  );

  // Real third-party application bytecode, when present on the host.
  let realJarClass;
  for (const jar of [
    "/usr/share/java/fontbox-1.8.16.jar",
    "/usr/share/java/pdfbox-1.8.16.jar",
  ]) {
    try {
      const extractDir = join(workspace, "realjar");
      await mkdir(extractDir, { recursive: true });
      const { stdout } = await execute("jar", ["tf", jar], {
        env: environment,
        maxBuffer: 32 * 1024 * 1024,
      });
      const entry = stdout
        .split("\n")
        .find((name) => name.endsWith(".class") && !name.includes("$"));
      if (entry === undefined) continue;
      await execute("jar", ["xf", jar, entry], {
        cwd: extractDir,
        env: environment,
      });
      realJarClass = join(extractDir, entry);
      break;
    } catch {
      /* try the next jar */
    }
  }
  if (realJarClass !== undefined) {
    const realReport = await inspectBoth(realJarClass);
    const realOracle = await javapFacts(realJarClass);
    assert.equal(
      realReport.methods.reduce(
        (total, m) => total + m.line_number_table.entries.length,
        0,
      ),
      realOracle.lineEntries,
      "real-jar LineNumberTable entry count != javap",
    );
    assert.equal(realReport.source_file.name, realOracle.sourceFile);
    for (const m of realReport.methods)
      assert.ok(
        realOracle.descriptors.has(m.descriptor),
        `real-jar descriptor ${m.descriptor} not reported by javap`,
      );
  }

  // Multi-release JAR: base + a release-17 override of the same class entry,
  // read through the JAR entry path (ZipArtifactReader + explicit selection).
  if (jarTool !== undefined) {
    const entry = "com/example/Service.class";
    const baseDir = join(workspace, "mr-base", "com", "example");
    const v17Dir = join(workspace, "mr-v17", "com", "example");
    await mkdir(baseDir, { recursive: true });
    await mkdir(v17Dir, { recursive: true });
    const svc = (body) =>
      `package com.example; class Service { int value(int a) { ${body} } }\n`;
    await writeFile(
      join(workspace, "mr-base", "Service.java"),
      svc("return a;"),
    );
    await writeFile(
      join(workspace, "mr-v17", "Service.java"),
      svc("int doubled = a * 2; return doubled;"),
    );
    const baseClasses = join(workspace, "mr-base-out");
    const v17Classes = join(workspace, "mr-v17-out");
    // A multi-release JAR's base must target a version no newer than its
    // versioned overrides, so build the base at 11 and the override at 17.
    await execute(
      javac,
      [
        "-g",
        "--release",
        "11",
        "-d",
        baseClasses,
        join(workspace, "mr-base", "Service.java"),
      ],
      { env: environment },
    );
    await execute(
      javac,
      [
        "-g",
        "--release",
        "17",
        "-d",
        v17Classes,
        join(workspace, "mr-v17", "Service.java"),
      ],
      { env: environment },
    );
    const jarPath = join(workspace, "app.jar");
    await execute(
      jarTool,
      [
        "--create",
        "--file",
        jarPath,
        "-C",
        baseClasses,
        ".",
        "--release",
        "17",
        "-C",
        v17Classes,
        ".",
      ],
      { env: environment },
    );

    // Omitted release -> base entry.
    const baseReport = await inspectBoth(jarPath, { entry });
    assert.equal(baseReport.container, "jar");
    assert.equal(baseReport.selected_entry.entry, entry);
    assert.equal(baseReport.selected_entry.release, null);
    assert.equal(baseReport.class.internal_name, "com/example/Service");
    assert.equal(baseReport.artifact.path, jarPath);

    // Explicit release 17 -> the versioned override, a distinct class body.
    const v17Report = await inspectBoth(jarPath, { entry, release: 17 });
    assert.equal(v17Report.selected_entry.release, 17);
    assert.notEqual(
      v17Report.selected_entry.sha256,
      baseReport.selected_entry.sha256,
      "release 17 override must differ from the base entry",
    );

    // An absent release is refused explicitly, never silently combined.
    const absent = await inspectCli(jarPath, { entry, release: 11 });
    assert.equal(absent.category, "invalid_input", JSON.stringify(absent));
    // A missing entry is reported as not found.
    const missing = await inspectCli(jarPath, {
      entry: "com/example/Nope.class",
    });
    assert.equal(missing.category, "invalid_input", JSON.stringify(missing));
    cases += 2;
  }

  // Error surfaces: non-class bytes and a truncated class file.
  const notClass = join(workspace, "notclass.bin");
  await writeFile(notClass, Buffer.from("not a class file at all"));
  const notClassCli = await inspectCli(notClass);
  assert.equal(
    notClassCli.category,
    "unsupported_target",
    JSON.stringify(notClassCli),
  );
  const notClassError = requireMcpToolError(await inspectMcp(notClass));
  assert.equal(notClassError.category, "unsupported_target");
  cases += 2;

  const truncated = join(workspace, "Truncated.class");
  await writeFile(truncated, original.subarray(0, 12));
  const truncatedCli = await inspectCli(truncated);
  assert.equal(
    truncatedCli.category,
    "invalid_input",
    JSON.stringify(truncatedCli),
  );
  const truncatedError = requireMcpToolError(await inspectMcp(truncated));
  assert.equal(truncatedError.category, "invalid_input");
  cases += 2;

  // The reader never mutates the selected bytes.
  assert.deepEqual(await readFile(gClass), original);
} catch (cause) {
  failures.push(cause);
}

try {
  await client.close();
} catch (cause) {
  failures.push(cause);
}
try {
  await transport.close();
} catch (cause) {
  failures.push(cause);
}
try {
  await rm(workspace, { recursive: true, force: true });
} catch (cause) {
  failures.push(cause);
}

if (failures.length > 0)
  throw new AggregateError(failures, "JVM debug-metadata verification failed.");
console.log(
  JSON.stringify(
    {
      status: "passed",
      cases,
      toolchain: "jdk-javac-javap",
      entrypoint,
      verifier: await completeVerifierRun(run),
    },
    null,
    2,
  ),
);
