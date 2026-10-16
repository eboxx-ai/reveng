import { rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect, it } from "vitest";

import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import { scanCanonicalArtifactInventory } from "../../../fixtures/artifactInventory.js";
import { readJavaScriptArtifactFiles } from "../../../support/javascriptApplicationScope.js";
import { createJavaScriptArtifactReader } from "../../../../src/artifacts/javascript/JavaScriptArtifactReader.js";
import { analyzeJavaScriptArtifactFiles } from "../../../../src/application/javascript/JavaScriptArtifactAnalysis.js";
import { buildJavaScriptArtifactGraph } from "../../../../src/application/javascript/JavaScriptArtifactGraphBuilder.js";

it("projects a qualified global socket with its source evidence and excludes a local lookalike", async () => {
  const root = await createTestTempDirectory("rea-js-qualified-socket-");
  await writeFile(
    join(root, "app.js"),
    [
      'function local(window) { new window.WebSocket("wss://example.test/local"); }',
      'new globalThis.WebSocket("wss://example.test/socket");',
    ].join("\n"),
  );
  const snapshot = await scanCanonicalArtifactInventory(root, {});
  const reader = createJavaScriptArtifactReader(root, "directory");
  try {
    const files = await readJavaScriptArtifactFiles(reader, snapshot);
    const analysis = analyzeJavaScriptArtifactFiles(files);
    const graph = buildJavaScriptArtifactGraph(snapshot, files, analysis);
    const endpoints = graph.nodes.filter(({ kind }) => kind === "endpoint");
    expect(endpoints).toHaveLength(1);
    const observation = endpoints[0]?.observations[0];
    expect(observation?.properties).toMatchObject({
      value: "wss://example.test/socket",
      mechanism: "call:globalThis.WebSocket",
    });
    expect(observation?.evidence).toMatchObject({
      authority: "ast-static-analysis",
      state: "observed",
      confidence: "exact",
      location: {
        available: true,
        value: {
          kind: "source-range",
          source: "app.js",
          start: { line: 2, column: 0 },
        },
      },
    });
  } finally {
    await reader.close();
    await rm(root, { recursive: true, force: true });
  }
});

it("retains constructor captures, ws imports and template keys with their graph source ranges", async () => {
  const root = await createTestTempDirectory("rea-js-bound-socket-");
  await writeFile(
    join(root, "app.js"),
    [
      'import Socket from "ws";',
      "const Captured = globalThis.WebSocket;",
      'new Socket("wss://example.test/imported");',
      'new Captured("wss://example.test/captured");',
      'new globalThis[`WebSocket`]("wss://example.test/template");',
      'const CommonJs = require("ws");',
      'new CommonJs("wss://example.test/commonjs");',
      "const { WebSocket: Projected } = globalThis;",
      'new Projected("wss://example.test/projected");',
      "function connect() {",
      'new Deferred("wss://example.test/deferred");',
      "}",
      "const Deferred = globalThis.WebSocket;",
      "connect();",
      'const { WebSocket: Named } = require("ws");',
      'new Named("wss://example.test/named-commonjs");',
      'const Member = require("ws").WebSocket;',
      'new Member("wss://example.test/member-commonjs");',
    ].join("\n"),
  );
  await writeFile(
    join(root, "import-equals.ts"),
    'import Socket = require("ws");\nnew Socket("wss://example.test/import-equals");',
  );
  const snapshot = await scanCanonicalArtifactInventory(root, {});
  const reader = createJavaScriptArtifactReader(root, "directory");
  try {
    const files = await readJavaScriptArtifactFiles(reader, snapshot);
    const analysis = analyzeJavaScriptArtifactFiles(files);
    const graph = buildJavaScriptArtifactGraph(snapshot, files, analysis);
    const endpoints = graph.nodes.filter(({ kind }) => kind === "endpoint");
    expect(endpoints).toHaveLength(9);
    for (const [path, constructor, line, source] of [
      ["imported", "Socket", 3, "app.js"],
      ["captured", "Captured", 4, "app.js"],
      ["template", "globalThis.WebSocket", 5, "app.js"],
      ["commonjs", "CommonJs", 7, "app.js"],
      ["projected", "Projected", 9, "app.js"],
      ["deferred", "Deferred", 11, "app.js"],
      ["import-equals", "Socket", 2, "import-equals.ts"],
      ["named-commonjs", "Named", 16, "app.js"],
      ["member-commonjs", "Member", 18, "app.js"],
    ] as const) {
      const observation = endpoints.find(({ observations }) =>
        observations.some(
          ({ properties }) => properties.value === `wss://example.test/${path}`,
        ),
      )?.observations[0];
      expect(observation?.properties).toMatchObject({
        value: `wss://example.test/${path}`,
        mechanism: `call:${constructor}`,
      });
      expect(observation?.evidence).toMatchObject({
        authority: "ast-static-analysis",
        state: "observed",
        confidence: "exact",
        location: {
          available: true,
          value: {
            kind: "source-range",
            source,
            start: { line, column: 0 },
          },
        },
      });
    }
  } finally {
    await reader.close();
    await rm(root, { recursive: true, force: true });
  }
});

const socketExecutionPhaseSources = {
  "review-getter.js":
    '({ get run() { new Socket("wss://example.test/review-getter"); return () => {}; } }).run(); const Socket = globalThis.WebSocket;',
  "review-pattern.mjs":
    'export {}; const { pending, unused = new (await pending).WebSocket("wss://example.test/review-pattern") } = { pending: import("ws") };',
  "review-label.js":
    '(async () => { label: { for (;;) { break; } await 0; } new Socket("wss://example.test/review-label"); })(); const Socket = globalThis.WebSocket;',
  "review-caught.mjs":
    'export {}; const pending=(async()=>{await 0;new Socket("wss://example.test/review-caught")})(); try { try {throw 0;} finally {} await pending; } catch {} const Socket=globalThis.WebSocket;',
  "review-capture.js":
    'const ws=require("ws");const {WebSocket:Socket,[(ws.WebSocket=class{},"x")]:ignored}=ws;new Socket("wss://example.test/review-capture");',
  "review-nested-loop.js":
    '(async()=>{do {while(true){break;} await 0;}while(false);new Socket("wss://example.test/review-nested-loop")})(); const Socket=globalThis.WebSocket;',
  "review-generator.js":
    'for(const ignored of (function*(){new Socket("wss://example.test/review-generator");yield 0;})()){} const Socket=globalThis.WebSocket;',
  "review-instance.js":
    '(new(class {run(){new Socket("wss://example.test/review-instance")}})()).run();const Socket=globalThis.WebSocket;',
  "phase-class.js":
    "(class { static run() { new Socket('wss://example.test/invalid-phase-class') } }).run(); const Socket = globalThis.WebSocket;",
  "phase-wrapper.js":
    "(async () => { const pending = (async () => { await 0; new Socket('wss://example.test/invalid-phase-wrapper') })(); await (() => pending)(); const Socket = globalThis.WebSocket; })();",
  "phase-label.js":
    "(async () => { label: { await 0; } new Socket('wss://example.test/phase-label') })(); const Socket = globalThis.WebSocket;",
  "phase-finally.js":
    "(async () => { try { throw await 0; } finally { new Socket('wss://example.test/phase-finally') } })(); const Socket = globalThis.WebSocket;",
  "phase-projection.mjs":
    "export {}; const { pending } = { pending: import('ws') }; const { WebSocket: Socket } = await pending; new Socket('wss://example.test/phase-projection');",
  "phase-accessor.ts":
    "const Client = class { accessor socket = new Socket('wss://example.test/phase-accessor') }; const Socket = globalThis.WebSocket; new Client();",
  "phase-jsx.jsx":
    "(async () => { <div>{await ready}</div>; new Socket('wss://example.test/phase-jsx'); })(); const Socket = globalThis.WebSocket;",
  "selected-call.js":
    '(true ? () => new Socket("wss://example.test/invalid-selected-call") : noop)(); const Socket = globalThis.WebSocket;',
  "import-source.js":
    '(async () => { import(await ready); new Socket("wss://example.test/import-source"); })(); const Socket = globalThis.WebSocket;',
  "case-coupled.js":
    '(async () => { switch (kind) { case 0: const pending = (async () => { await ready; new Socket("wss://example.test/invalid-case-coupled"); })(); await pending; } const Socket = globalThis.WebSocket; })();',
  "fresh-method.js":
    '({ run() { new Socket("wss://example.test/invalid-fresh-method"); } }).run(); const Socket = globalThis.WebSocket;',
  "decorator.ts":
    '@(function () { new Socket("wss://example.test/invalid-decorator"); }) class Client {}; const Socket = globalThis.WebSocket;',
  "selected-stored.js":
    'const connect = (true ? () => new Socket("wss://example.test/selected-stored") : noop); const Socket = globalThis.WebSocket; connect();',
  "import-no-wait.js":
    '(async () => { import("owned:module"); new Socket("wss://example.test/invalid-import-no-wait"); })(); const Socket = globalThis.WebSocket;',
  "case-skipped.js":
    '(async () => { switch (kind) { case 0: const pending = (async () => { await ready; new Socket("wss://example.test/case-skipped"); })(); break; await pending; } const Socket = globalThis.WebSocket; })();',
  "blocking-wrapper.mjs":
    'const pending = (async () => { await 0; new Socket("wss://example.test/invalid-blocking-wrapper"); })(); await (async () => { await pending; })(); const Socket = globalThis.WebSocket;',
  "suspended-blocking-wrapper.mjs":
    'const pending = (async () => { await 0; new Socket("wss://example.test/invalid-suspended-wrapper"); })(); await (async () => { await 0; await pending; })(); const Socket = globalThis.WebSocket;',
  "unawaited-wrapper.js":
    'const pending = (async () => { await 0; new Socket("wss://example.test/unawaited-wrapper"); })(); (async () => { await pending; })(); const Socket = globalThis.WebSocket;',
  "optional-wrapper.mjs":
    'const pending = (async () => { await ready; new Socket("wss://example.test/optional-wrapper"); })(); await (async () => { if (condition) await pending; })(); const Socket = globalThis.WebSocket;',
  "caught-alias.mjs":
    'const pending = (async () => { await 0; new Socket("wss://example.test/caught-alias"); })(); try { await alias; } catch {} const alias = pending; const Socket = globalThis.WebSocket;',
  "dead-wait.js":
    '(async () => { const pending = (async () => { await ready; new Socket("wss://example.test/dead-wait"); })(); while (true) { break; await pending; } const Socket = globalThis.WebSocket; })();',
  "logical-rhs.js":
    '(async () => { (await ready).value &&= new Socket("wss://example.test/logical-assignment"); })(); const Socket = globalThis.WebSocket;',
  "case-prefix.js":
    '(async () => { switch (kind) { case 0: await ready; new Socket("wss://example.test/case-prefix"); } })(); const Socket = globalThis.WebSocket;',
  "rebound-import.ts":
    'import ws = require("ws"); const other = require("ws"); ws = {}; ws.WebSocket = class {}; new other.WebSocket("wss://example.test/rebound-import");',
  "branch-alias.js":
    '(async () => { if (condition) { const pending = (async () => { await ready; new Socket("wss://example.test/invalid-branch-alias"); })(); await pending; } const Socket = globalThis.WebSocket; })();',
  "escaped-literal.js":
    'let box; const { unused = (box.WebSocket = class {}), WebSocket: Socket } = (box = { WebSocket: globalThis.WebSocket }); new Socket("wss://example.test/invalid-escaped");',
  "replaced-iterator.js":
    'Array.prototype[Symbol.iterator] = function* () { yield class {}; }; const [Socket] = [globalThis.WebSocket]; new Socket("wss://example.test/invalid-iterator");',
  "ordinary-call.js":
    'globalThis.WebSocket("wss://example.test/invalid-call");',
  "resource-registration.js":
    '(async () => { try { using resource = 1; await 0; } finally { new Socket("wss://example.test/invalid-using"); } })(); const Socket = globalThis.WebSocket;',
  "finally-entry.js":
    '(async () => { try { await 0; } finally { new Socket("wss://example.test/finally-entry"); } })(); const Socket = globalThis.WebSocket;',
  "wrapped-array.js":
    'const [Socket] = (0, [globalThis.WebSocket]); new Socket("wss://example.test/wrapped-array");',
  "switch-await.js":
    '(async () => { switch (await ready) { default: new Socket("wss://example.test/switch-await"); } })(); const Socket = globalThis.WebSocket;',
  "optional-argument.js":
    '(async () => { (await ready)?.(new Socket("wss://example.test/optional-argument")); })(); const Socket = globalThis.WebSocket;',
  "update-operand.js":
    '(async () => { (await ready).count++; new Socket("wss://example.test/update-operand"); })(); const Socket = globalThis.WebSocket;',
  "nested-write.js":
    'const ws = require("ws"); const Socket = ws.WebSocket; if (flag) { ws.WebSocket = Fake; } new Socket("wss://example.test/nested-write");',
  "ws-self.js":
    'const ws = require("ws"); new ws.WebSocket.WebSocket("wss://example.test/ws-self");',
  "exact-result-write.js":
    'let holder; const ws = (holder = require("ws")); ws.WebSocket = Fake; new ws.WebSocket("wss://example.test/invalid-exact-write");',
  "conditional-producer.js":
    '(async () => { if (condition) await (async () => { await ready; new Socket("wss://example.test/invalid-wait"); })(); const Socket = globalThis.WebSocket; })();',
  "implicit-await.js":
    '(async () => { for await (const item of [0]) { new Socket("wss://example.test/implicit-await"); } })(); const Socket = globalThis.WebSocket;',
  "do-await.js":
    '(async () => { do { await ready; } while (false); new Socket("wss://example.test/do-await"); })(); const Socket = globalThis.WebSocket;',
  "try-await.js":
    '(async () => { try { await ready; } finally {} new Socket("wss://example.test/try-await"); })(); const Socket = globalThis.WebSocket;',
  "update-await.js":
    '(async () => { for (let i = 0; i < 1; new Socket("wss://example.test/update-await"), i++) { await ready; } })(); const Socket = globalThis.WebSocket;',
  "pattern-await.js":
    '(async () => { const {[await 0]: value} = {}; new Socket("wss://example.test/pattern-await"); })(); const Socket = globalThis.WebSocket;',
  "binding-event.js":
    'const { WebSocket: Socket, unused = new Socket("wss://example.test/binding-event") } = globalThis;',
  "copy-order.js":
    'const ws = require("ws"); const { WebSocket: Socket } = { WebSocket: ws.WebSocket, later: (ws.WebSocket = class {}) }; new Socket("wss://example.test/copy-order");',
  "binding-before-event.js":
    'const { unused = new Socket("wss://example.test/tdz-binding-event"), WebSocket: Socket } = globalThis;',
  "do-skipped-await.js":
    '(async () => { do { break; await ready; } while (false); new Socket("wss://example.test/tdz-do-jump"); })(); const Socket = globalThis.WebSocket;',
  "tag-eager.js":
    '(function () { new Socket("wss://example.test/tdz-tag"); })``; const Socket = globalThis.WebSocket;',
  "tag-generator.js":
    '(function* () { new Socket("wss://example.test/tag-generator"); })``; const Socket = globalThis.WebSocket;',
  "template.js":
    '(async () => { `${await ready}`; new Socket("wss://example.test/template-continuation"); })(); const Socket = globalThis.WebSocket;',
  "iterable.js":
    '(async () => { for (const item of await ready) {} new Socket("wss://example.test/iterable-continuation"); })(); const Socket = globalThis.WebSocket;',
  "iterable-body.js":
    '(async () => { for (const key in await ready) { new Socket("wss://example.test/iterable-body"); } })(); const Socket = globalThis.WebSocket;',
  "assignment-capture.js":
    'let holder; const Socket = (holder = globalThis.WebSocket); new Socket("wss://example.test/assignment-capture");',
  "numeric-object.js":
    'const [Socket] = { 0: globalThis.WebSocket }; new Socket("wss://example.test/tdz-noniterable");',
  "object-key.js":
    'const { 0: Socket } = { 0: globalThis.WebSocket }; new Socket("wss://example.test/object-key");',
  "wrapped.ts":
    '(function () { new Socket("wss://example.test/eager-wrapper"); } as any)();\nconst Socket = globalThis.WebSocket;',
  "fields.js":
    'class Client { socket = new Socket("wss://example.test/field"); }\nconst Socket = globalThis.WebSocket; new Client();',
  "generator.js":
    '(function* (x = new Socket("wss://example.test/eager-parameter")) {})();\n(function* () { new Socket("wss://example.test/generator-body"); })();\nconst Socket = globalThis.WebSocket;',
  "bound.js":
    '(function () { new Socket("wss://example.test/eager-bind"); }).bind(null)();\nconst connect = (function () { new Socket("wss://example.test/deferred-bind"); }).bind(null);\nconst Socket = globalThis.WebSocket; connect();',
  "async.js":
    '(async () => { new Socket("wss://example.test/eager-async"); await ready; })();\n(async () => { await ready; new Socket("wss://example.test/continuation"); })();\nconst Socket = globalThis.WebSocket;',
  "await-inputs.js": [
    'let value; (async () => { value = await ready; new Socket("wss://example.test/assignment"); })();',
    '(async () => { new (class { socket = new Socket("wss://example.test/argument-field"); })(await ready); })();',
    '(async () => { new (class { constructor() { new Socket("wss://example.test/argument-constructor"); } })(await ready); })();',
    '(async () => { new (class { socket = new Socket("wss://example.test/computed-key"); [await ready] = 0; })(); })();',
    "const Socket = globalThis.WebSocket;",
  ].join("\n"),
  "immediate-generator.js":
    '(function* () { new Socket("wss://example.test/tdz-generator"); })().next(); const Socket = globalThis.WebSocket;',
  "delegated-generator.js":
    '(function* () { yield* []; new Socket("wss://example.test/tdz-delegation"); })().next(); const Socket = globalThis.WebSocket;',
  "waiting-caller.js":
    '(async () => { await (async () => { await ready; new Socket("wss://example.test/tdz-waiting"); })(); const Socket = globalThis.WebSocket; })();',
  "switch-case.js":
    'switch (kind) { case 0: const Socket = globalThis.WebSocket; break; case 1: new Socket("wss://example.test/tdz-case"); }',
  "loop-array.js": [
    '(async () => { while (await ready) { new Socket("wss://example.test/loop-continuation"); break; } })();',
    '(async () => { [await ready, new Socket("wss://example.test/array-continuation")]; })();',
    "const Socket = globalThis.WebSocket;",
  ].join("\n"),
  "sequence-capture.js":
    'const Socket = (0, globalThis.WebSocket); new Socket("wss://example.test/sequence-capture");',
  "dynamic-import.mjs":
    'const { WebSocket: Socket } = await import("ws"); new Socket("wss://example.test/dynamic-import");',
  "object-await.js":
    '(async () => { ({ first: await ready, second: new Socket("wss://example.test/object-continuation") }); })(); const Socket = globalThis.WebSocket;',
  "pending-before.mjs":
    'const pending = (async () => { await ready; new Socket("wss://example.test/tdz-pending"); })(); await pending; const Socket = globalThis.WebSocket;',
  "pending-after.mjs":
    'const pending = (async () => { await ready; new Socket("wss://example.test/pending-initialized"); })(); const Socket = globalThis.WebSocket; await pending;',
  "import-alias.mjs":
    'const pending = import("ws"); const { WebSocket: Socket } = await pending; new Socket("wss://example.test/import-alias");',
  "skipped-wait.mjs":
    'const pending = (async () => { await 0; new Socket("wss://example.test/skipped-wait"); })(); if (false) await pending; const Socket = globalThis.WebSocket;',
  "member-await.js":
    '(async () => { const value = (await ready).value; new Socket("wss://example.test/member-await"); })(); const Socket = globalThis.WebSocket;',
  "optional-capture.js":
    'const Socket = globalThis?.WebSocket; new Socket("wss://example.test/optional-capture");',
  "selected-branch.js":
    '(async () => { if (true) await ready; new Socket("wss://example.test/selected-branch"); })(); const Socket = globalThis.WebSocket;',
  "compound-continuation.js":
    '(async () => { let count = 0; count += await ready; new Socket("wss://example.test/compound-continuation"); })(); const Socket = globalThis.WebSocket;',
  "compound-wait.mjs":
    'const pending = (async () => { await 0; new Socket("wss://example.test/tdz-compound-wait"); })(); let count = 0; count += await pending; const Socket = globalThis.WebSocket;',
  "optional-call.js":
    '(async () => { (await ready)?.(); new Socket("wss://example.test/optional-call"); })(); const Socket = globalThis.WebSocket;',
  "logical-assignment.js":
    '(async () => { let count = 0; count &&= await ready; new Socket("wss://example.test/tdz-logical-assignment"); })(); const Socket = globalThis.WebSocket;',
  "import-equals-member.ts":
    'import ws = require("ws"); const Socket = ws.WebSocket; new Socket("wss://example.test/import-equals-member");',
  "import-equals-written.ts":
    'import ws = require("ws"); ws.WebSocket = class {}; const Socket = ws.WebSocket; new Socket("wss://example.test/tdz-import-equals-write");',
  "array-projection.js":
    'const [[Socket]] = [[globalThis.WebSocket]]; new Socket("wss://example.test/array-projection");',
  "assigned-call.js":
    'let connect; (connect = () => new Socket("wss://example.test/tdz-assignment"))(); const Socket = globalThis.WebSocket;',
  "await-branch.js":
    '(async () => { if (await ready) new Socket("wss://example.test/branch-continuation"); })(); const Socket = globalThis.WebSocket;',
  "immediate-sequence.js":
    '(0, function () { new Socket("wss://example.test/tdz-sequence"); })(); const Socket = globalThis.WebSocket;',
  "async-local.js":
    '(async () => { new Socket("wss://example.test/tdz-before-await"); await ready; const Socket = globalThis.WebSocket; })();',
  "async-phases.js":
    '(async () => { await ready; new Socket("wss://example.test/tdz-between-awaits"); await ready; const Socket = globalThis.WebSocket; })();',
  "immediate-class.js":
    'new (class { socket = new Socket("wss://example.test/tdz-field"); })(); const Socket = globalThis.WebSocket;',
  "immediate-constructor.js":
    'new (class { constructor() { new Socket("wss://example.test/tdz-constructor"); } })(); const Socket = globalThis.WebSocket;',
};

const socketExecutionPhaseLocations = [
  ["review-capture", "review-capture.js", 1],
  ["review-caught", "review-caught.mjs", 1],
  ["review-label", "review-label.js", 1],
  ["review-nested-loop", "review-nested-loop.js", 1],
  ["review-pattern", "review-pattern.mjs", 1],
  ["phase-label", "phase-label.js", 1],
  ["phase-finally", "phase-finally.js", 1],
  ["phase-projection", "phase-projection.mjs", 1],
  ["phase-accessor", "phase-accessor.ts", 1],
  ["phase-jsx", "phase-jsx.jsx", 1],
  ["case-skipped", "case-skipped.js", 1],
  ["import-source", "import-source.js", 1],
  ["selected-stored", "selected-stored.js", 1],
  ["unawaited-wrapper", "unawaited-wrapper.js", 1],
  ["optional-wrapper", "optional-wrapper.mjs", 1],
  ["caught-alias", "caught-alias.mjs", 1],
  ["dead-wait", "dead-wait.js", 1],
  ["logical-assignment", "logical-rhs.js", 1],
  ["case-prefix", "case-prefix.js", 1],
  ["rebound-import", "rebound-import.ts", 1],
  ["finally-entry", "finally-entry.js", 1],
  ["wrapped-array", "wrapped-array.js", 1],
  ["switch-await", "switch-await.js", 1],
  ["optional-argument", "optional-argument.js", 1],
  ["update-operand", "update-operand.js", 1],
  ["nested-write", "nested-write.js", 1],
  ["ws-self", "ws-self.js", 1],
  ["implicit-await", "implicit-await.js", 1],
  ["do-await", "do-await.js", 1],
  ["try-await", "try-await.js", 1],
  ["update-await", "update-await.js", 1],
  ["pattern-await", "pattern-await.js", 1],
  ["binding-event", "binding-event.js", 1],
  ["copy-order", "copy-order.js", 1],
  ["assignment-capture", "assignment-capture.js", 1],
  ["iterable-body", "iterable-body.js", 1],
  ["iterable-continuation", "iterable.js", 1],
  ["object-key", "object-key.js", 1],
  ["tag-generator", "tag-generator.js", 1],
  ["template-continuation", "template.js", 1],
  ["assignment", "await-inputs.js", 1],
  ["argument-field", "await-inputs.js", 2],
  ["argument-constructor", "await-inputs.js", 3],
  ["computed-key", "await-inputs.js", 4],
  ["branch-continuation", "await-branch.js", 1],
  ["continuation", "async.js", 2],
  ["deferred-bind", "bound.js", 2],
  ["field", "fields.js", 1],
  ["generator-body", "generator.js", 2],
  ["array-continuation", "loop-array.js", 2],
  ["loop-continuation", "loop-array.js", 1],
  ["sequence-capture", "sequence-capture.js", 1],
  ["dynamic-import", "dynamic-import.mjs", 1],
  ["object-continuation", "object-await.js", 1],
  ["pending-initialized", "pending-after.mjs", 1],
  ["import-alias", "import-alias.mjs", 1],
  ["skipped-wait", "skipped-wait.mjs", 1],
  ["member-await", "member-await.js", 1],
  ["optional-capture", "optional-capture.js", 1],
  ["selected-branch", "selected-branch.js", 1],
  ["compound-continuation", "compound-continuation.js", 1],
  ["optional-call", "optional-call.js", 1],
  ["import-equals-member", "import-equals-member.ts", 1],
  ["array-projection", "array-projection.js", 1],
] as const;

it("preserves eager and deferred socket phases through filesystem graph projection", async () => {
  const root = await createTestTempDirectory("rea-js-socket-phases-");
  for (const [path, source] of Object.entries(socketExecutionPhaseSources))
    await writeFile(join(root, path), source);
  const snapshot = await scanCanonicalArtifactInventory(root, {});
  const reader = createJavaScriptArtifactReader(root, "directory");
  try {
    const files = await readJavaScriptArtifactFiles(reader, snapshot);
    const analysis = analyzeJavaScriptArtifactFiles(files);
    const graph = buildJavaScriptArtifactGraph(snapshot, files, analysis);
    const observations = graph.nodes
      .filter(({ kind }) => kind === "endpoint")
      .flatMap(({ observations }) => observations);
    expect(
      observations.map(({ properties }) => properties.value).sort(),
    ).toEqual([
      "wss://example.test/argument-constructor",
      "wss://example.test/argument-field",
      "wss://example.test/array-continuation",
      "wss://example.test/array-projection",
      "wss://example.test/assignment",
      "wss://example.test/assignment-capture",
      "wss://example.test/binding-event",
      "wss://example.test/branch-continuation",
      "wss://example.test/case-prefix",
      "wss://example.test/case-skipped",
      "wss://example.test/caught-alias",
      "wss://example.test/compound-continuation",
      "wss://example.test/computed-key",
      "wss://example.test/continuation",
      "wss://example.test/copy-order",
      "wss://example.test/dead-wait",
      "wss://example.test/deferred-bind",
      "wss://example.test/do-await",
      "wss://example.test/dynamic-import",
      "wss://example.test/field",
      "wss://example.test/finally-entry",
      "wss://example.test/generator-body",
      "wss://example.test/implicit-await",
      "wss://example.test/import-alias",
      "wss://example.test/import-equals-member",
      "wss://example.test/import-source",
      "wss://example.test/iterable-body",
      "wss://example.test/iterable-continuation",
      "wss://example.test/logical-assignment",
      "wss://example.test/loop-continuation",
      "wss://example.test/member-await",
      "wss://example.test/nested-write",
      "wss://example.test/object-continuation",
      "wss://example.test/object-key",
      "wss://example.test/optional-argument",
      "wss://example.test/optional-call",
      "wss://example.test/optional-capture",
      "wss://example.test/optional-wrapper",
      "wss://example.test/pattern-await",
      "wss://example.test/pending-initialized",
      "wss://example.test/phase-accessor",
      "wss://example.test/phase-finally",
      "wss://example.test/phase-jsx",
      "wss://example.test/phase-label",
      "wss://example.test/phase-projection",
      "wss://example.test/rebound-import",
      "wss://example.test/review-capture",
      "wss://example.test/review-caught",
      "wss://example.test/review-label",
      "wss://example.test/review-nested-loop",
      "wss://example.test/review-pattern",
      "wss://example.test/selected-branch",
      "wss://example.test/selected-stored",
      "wss://example.test/sequence-capture",
      "wss://example.test/skipped-wait",
      "wss://example.test/switch-await",
      "wss://example.test/tag-generator",
      "wss://example.test/template-continuation",
      "wss://example.test/try-await",
      "wss://example.test/unawaited-wrapper",
      "wss://example.test/update-await",
      "wss://example.test/update-operand",
      "wss://example.test/wrapped-array",
      "wss://example.test/ws-self",
    ]);
    for (const [path, source, line] of socketExecutionPhaseLocations) {
      const observation = observations.find(
        ({ properties }) => properties.value === `wss://example.test/${path}`,
      );
      expect(observation?.evidence).toMatchObject({
        authority: "ast-static-analysis",
        state: "observed",
        confidence: "exact",
        location: {
          available: true,
          value: { kind: "source-range", source, start: { line } },
        },
      });
    }
  } finally {
    await reader.close();
    await rm(root, { recursive: true, force: true });
  }
});

it("keeps CommonJS socket member writes separate from earlier constructor captures", async () => {
  const root = await createTestTempDirectory("rea-js-socket-member-writes-");
  const fixtures = {
    "replaced.js":
      'const ws = require("ws"); ws.WebSocket = class {}; new ws.WebSocket("wss://example.test/replaced");',
    "aliased.js":
      'const ws = require("ws"); const alias = ws; alias.WebSocket = class {}; new ws.WebSocket("wss://example.test/aliased");',
    "repeated.js":
      'require("ws").WebSocket = class {}; const ws = require("ws"); new ws.WebSocket("wss://example.test/repeated");',
    "captured.js":
      'const ws = require("ws"); const Socket = ws.WebSocket; ws.WebSocket = class {};\nnew Socket("wss://example.test/captured-before-write");',
    "loop-capture.js":
      'const ws = require("ws"); const Socket = ws.WebSocket; for (const item of items) { ws.WebSocket = class {}; }\nnew Socket("wss://example.test/loop-captured");',
    "sibling.js":
      'const ws = require("ws"); ws.Server = class {};\nnew ws.WebSocket("wss://example.test/unchanged-sibling");',
  };
  for (const [path, source] of Object.entries(fixtures))
    await writeFile(join(root, path), source);
  const snapshot = await scanCanonicalArtifactInventory(root, {});
  const reader = createJavaScriptArtifactReader(root, "directory");
  try {
    const files = await readJavaScriptArtifactFiles(reader, snapshot);
    const graph = buildJavaScriptArtifactGraph(
      snapshot,
      files,
      analyzeJavaScriptArtifactFiles(files),
    );
    const observations = graph.nodes
      .filter(({ kind }) => kind === "endpoint")
      .flatMap(({ observations }) => observations);
    expect(
      observations.map(({ properties }) => properties.value).sort(),
    ).toEqual([
      "wss://example.test/captured-before-write",
      "wss://example.test/loop-captured",
      "wss://example.test/unchanged-sibling",
    ]);
    for (const [value, source] of [
      ["captured-before-write", "captured.js"],
      ["loop-captured", "loop-capture.js"],
      ["unchanged-sibling", "sibling.js"],
    ]) {
      const observation = observations.find(
        ({ properties }) => properties.value === `wss://example.test/${value}`,
      );
      expect(observation?.evidence).toMatchObject({
        authority: "ast-static-analysis",
        state: "observed",
        confidence: "exact",
        location: {
          available: true,
          value: { kind: "source-range", source, start: { line: 2 } },
        },
      });
    }
  } finally {
    await reader.close();
    await rm(root, { recursive: true, force: true });
  }
});

it("keeps ambiguous endpoint candidates inferred through artifact graph projection", async () => {
  const root = await createTestTempDirectory("rea-js-endpoint-certainty-");
  await writeFile(join(root, "app.js"), 'form.get("shared"); fetch("shared");');
  const snapshot = await scanCanonicalArtifactInventory(root, {});
  const reader = createJavaScriptArtifactReader(root, "directory");
  try {
    const files = await readJavaScriptArtifactFiles(reader, snapshot);
    const analysis = analyzeJavaScriptArtifactFiles(files);
    const graph = buildJavaScriptArtifactGraph(snapshot, files, analysis);
    const endpoints = graph.nodes.filter(({ kind }) => kind === "endpoint");
    const candidate = endpoints.find(({ observations }) =>
      observations.some(
        ({ properties }) => properties.interpretation === "candidate",
      ),
    );
    const observed = endpoints.find(({ observations }) =>
      observations.some(
        ({ properties }) =>
          properties.value === "shared" &&
          properties.interpretation === undefined,
      ),
    );

    expect(candidate).toBeDefined();
    expect(observed).toBeDefined();
    expect(candidate?.node_id).not.toBe(observed?.node_id);
    const candidateObservation = candidate?.observations[0];
    expect(candidateObservation?.properties).toMatchObject({
      value: "shared",
      interpretation: "candidate",
    });
    expect(candidateObservation?.evidence).toMatchObject({
      authority: "static-relationship-inference",
      state: "inferred",
      confidence: "low",
      location: {
        available: true,
        value: { kind: "source-range", source: "app.js" },
      },
    });
    expect(candidateObservation?.evidence.limitations).toEqual(
      expect.arrayContaining([expect.stringContaining("only a candidate")]),
    );
    expect(observed?.observations[0]?.evidence).toMatchObject({
      authority: "ast-static-analysis",
      state: "observed",
      confidence: "exact",
    });
    const candidateEdge = graph.edges.find(
      ({ target_node_id }) => target_node_id === candidate?.node_id,
    );
    expect(candidateEdge?.properties.interpretation).toBe("candidate");
    expect(candidateEdge?.evidence).toMatchObject({
      state: "inferred",
      confidence: "low",
    });
    expect(candidateEdge?.evidence.limitations).toEqual(
      expect.arrayContaining([expect.stringContaining("only a candidate")]),
    );
  } finally {
    await reader.close();
    await rm(root, { recursive: true, force: true });
  }
});

it("preserves partial and exact endpoint identity through graph projection", async () => {
  const root = await createTestTempDirectory(
    "rea-js-endpoint-partial-identity-",
  );
  await writeFile(
    join(root, "app.js"),
    'fetch(target); fetch("target"); function other(target) { fetch(target); }',
  );
  const snapshot = await scanCanonicalArtifactInventory(root, {});
  const reader = createJavaScriptArtifactReader(root, "directory");
  try {
    const files = await readJavaScriptArtifactFiles(reader, snapshot);
    const analysis = analyzeJavaScriptArtifactFiles(files);
    const graph = buildJavaScriptArtifactGraph(snapshot, files, analysis);
    const endpoints = graph.nodes.filter(({ kind }) => kind === "endpoint");
    const partialNodes = endpoints.filter(({ observations }) =>
      observations.some(
        ({ properties }) => properties.resolution === "partial",
      ),
    );
    const partial = partialNodes[0];
    const exact = endpoints.find(({ observations }) =>
      observations.some(
        ({ properties }) =>
          properties.value === "target" && properties.resolution === undefined,
      ),
    );

    expect(partialNodes).toHaveLength(2);
    expect(new Set(partialNodes.map(({ node_id }) => node_id)).size).toBe(2);
    expect(exact).toBeDefined();
    expect(partial?.node_id).not.toBe(exact?.node_id);
    expect(partial?.observations[0]).toMatchObject({
      properties: {
        endpoint_kind: "network",
        value: "target",
        mechanism: "call:fetch",
        resolution: "partial",
      },
      evidence: {
        authority: "ast-static-analysis",
        state: "observed",
        limitations: [expect.stringContaining("not an exact literal")],
      },
    });
  } finally {
    await reader.close();
    await rm(root, { recursive: true, force: true });
  }
});

const completedWriteAndConsumerSources = [
  {
    file: "invocation-review-0.js",
    source:
      'new(class{constructor([x]){}})((function*(){new Socket("wss://example.test/review-latest");yield 0;})());const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    file: "invocation-review-1.js",
    source:
      '(async()=>{try{throw 0;}catch{await 0;}new Socket("wss://example.test/review-latest");})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    file: "invocation-review-2.js",
    source:
      '(async()=>{const pending=(async()=>{await ready;new Socket("wss://example.test/review-latest");})();await(()=>pending)?.();const Socket=globalThis.WebSocket;})();',
    present: false,
  },
  {
    file: "invocation-review-3.js",
    source:
      '(async()=>{const [{[await 0]:x},next]=(function*(){yield null;new Socket("wss://example.test/review-latest");})();})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    file: "iteration-review-0.js",
    source:
      'const holder={};(holder.run=()=>new Socket("wss://example.test/review-latest"))();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    file: "iteration-review-1.js",
    source:
      'Array.prototype[Symbol.iterator]=function*(){yield 1;};(async()=>{const [[x=await 0],next]=(function*(){yield [undefined];new Socket("wss://example.test/review-latest");yield 1;})();})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    file: "iteration-review-2.js",
    source:
      '(async()=>{({})?.[await ready];new Socket("wss://example.test/review-latest");})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    file: "iteration-review-3.js",
    source:
      '(async()=>{const [[x=await 0],next]=(function*(){yield [];new Socket("wss://example.test/review-latest");yield 1;})();})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    file: "iteration-review-4.js",
    source:
      '(async()=>{let x;[...[x=await 0,({set run(v){new Socket("wss://example.test/review-latest");}}).run]]=[undefined,0];})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    file: "iteration-review-5.js",
    source:
      '(function([x]){})((function*(){new Socket("wss://example.test/review-latest");yield 0;})());const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    file: "phase-review-0.js",
    source:
      '((()=>0)(),()=>new Socket("wss://example.test/review-latest"))();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    file: "phase-review-1.js",
    source:
      '(async()=>{const [{[await 0]:value},next]=(function*(){yield {};new Socket("wss://example.test/review-latest");yield 1;})();})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    file: "phase-review-2.js",
    source:
      '({set run(value){new Socket("wss://example.test/review-latest");}}).run=0;const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    file: "phase-review-3.js",
    source:
      '(async()=>{try{await using resource=null;}finally{new Socket("wss://example.test/review-latest");}})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    file: "phase-review-4.js",
    source:
      'function marker(){};new(marker,globalThis.WebSocket)("wss://example.test/review-latest");',
    present: true,
  },
  {
    file: "phase-review-5.js",
    source:
      '(async()=>{try{await 0;}catch{}new Socket("wss://example.test/review-latest");})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    file: "phase-review-6.js",
    source:
      '(async()=>{do{await 0;break;}while(false);new Socket("wss://example.test/review-latest");})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    file: "phase-review-7.js",
    source:
      '(async()=>{exit:{await using r=null;break exit;}new Socket("wss://example.test/review-latest");})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    file: "review-0.js",
    source:
      'const holder = 0; new (holder = globalThis.WebSocket)("wss://example.test/review-latest");',
    present: false,
  },
  {
    file: "review-1.js",
    source:
      '[...(function* () { new Socket("wss://example.test/review-latest"); yield 0; })()]; const Socket = globalThis.WebSocket;',
    present: false,
  },
  {
    file: "review-2.js",
    source:
      '(async () => { const pending = (async () => { await ready; new Socket("wss://example.test/review-latest"); })(); try { null.value; await pending; } catch {} const Socket = globalThis.WebSocket; })();',
    present: true,
  },
  {
    file: "review-3.js",
    source:
      '(async () => { with ({}) { await ready; } new Socket("wss://example.test/review-latest"); })(); const Socket = globalThis.WebSocket;',
    present: true,
  },
  {
    file: "review-4.js",
    source:
      'new globalThis.globalThis.WebSocket("wss://example.test/review-latest");',
    present: true,
  },
  {
    file: "review-5.js",
    source:
      'const ws = require("ws"); const object = { [new ws.WebSocket("wss://example.test/review-latest")]: (ws.WebSocket = class {}) };',
    present: true,
  },
  {
    file: "review-6.js",
    source:
      '(async () => { for (const item of (function* () { yield 0; new Socket("wss://example.test/review-latest"); })()) { await using resource = null; } })(); const Socket = globalThis.WebSocket;',
    present: true,
  },
  {
    file: "scope-review-0.js",
    source:
      '(async () => { { await using resource = null; } new Socket("wss://example.test/review-latest"); })(); const Socket = globalThis.WebSocket;',
    present: true,
  },
  {
    file: "scope-review-1.js",
    source:
      'export {}; try { const pending = (async () => { await 0; new Socket("wss://example.test/review-latest"); })(); await pending; const Socket = globalThis.WebSocket; } catch {}',
    present: false,
  },
  {
    file: "scope-review-2.js",
    source:
      'let connect; (() => { (connect = () => new Socket("wss://example.test/review-latest"))(); })(); const Socket = globalThis.WebSocket;',
    present: false,
  },
  {
    file: "scope-review-3.js",
    source:
      'for (let holder of [new (holder = globalThis.WebSocket)("wss://example.test/review-latest")]) {}',
    present: false,
  },
  {
    file: "scope-review-4.js",
    source:
      'const [ignored] = (function* () { new Socket("wss://example.test/review-latest"); yield 0; })(); const Socket = globalThis.WebSocket;',
    present: false,
  },
  {
    file: "scope-review-5.js",
    source:
      '(async () => { switch (kind) { case await ready: new Socket("wss://example.test/review-latest"); } })(); const Socket = globalThis.WebSocket;',
    present: true,
  },
  {
    file: "scope-review-6.js",
    source:
      '(async () => { (async (_x) => { new Socket("wss://example.test/review-latest"); })?.(await ready); })(); const Socket = globalThis.WebSocket;',
    present: true,
  },
  {
    file: "consumption-review-0.js",
    source:
      '(async()=>{const [a,b=await 0,c]=(function*(){yield 0;new Socket("wss://example.test/review-latest");yield undefined;yield 2})()})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    file: "consumption-review-1.js",
    source:
      '({get run(){new Socket("wss://example.test/review-latest")}}).run=0;const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    file: "consumption-review-2.js",
    source:
      'new(null.value,globalThis.WebSocket)("wss://example.test/review-latest");',
    present: false,
  },
  {
    file: "consumption-review-3.js",
    source:
      '(async()=>{(()=>{})?.(await ready);new Socket("wss://example.test/review-latest")})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    file: "consumption-review-4.js",
    source:
      '(async()=>{const pending=(async()=>{await ready;new Socket("wss://example.test/review-latest")})();while(true){if(skip)break;await pending;break;}const Socket=globalThis.WebSocket;})();',
    present: true,
  },
  {
    file: "consumption-review-5.js",
    source:
      '(async()=>{const pending=(async()=>{await ready;new Socket("wss://example.test/review-latest")})();await(async()=>pending)();const Socket=globalThis.WebSocket;})();',
    present: false,
  },
  {
    file: "consumption-review-6.js",
    source:
      '(function*(){yield*(function*(){new Socket("wss://example.test/review-latest");yield 0})()})().next();const Socket=globalThis.WebSocket;',
    present: false,
  },
];

it("retains reviewed completion endpoints with filesystem source provenance", async () => {
  const root = await createTestTempDirectory("rea-reviewed-completion-");
  for (const { file, source } of completedWriteAndConsumerSources)
    await writeFile(join(root, file), source);
  const snapshot = await scanCanonicalArtifactInventory(root, {});
  const reader = createJavaScriptArtifactReader(root, "directory");
  try {
    const files = await readJavaScriptArtifactFiles(reader, snapshot);
    const analysis = analyzeJavaScriptArtifactFiles(files);
    const graph = buildJavaScriptArtifactGraph(snapshot, files, analysis);
    const observations = graph.nodes
      .filter((node) => node.kind === "endpoint")
      .flatMap((node) => node.observations);
    expect(observations).toHaveLength(21);
    for (const { file, present } of completedWriteAndConsumerSources) {
      const matching = observations.filter(
        ({ evidence }) =>
          evidence.location.available &&
          evidence.location.value.kind === "source-range" &&
          evidence.location.value.source === file,
      );
      expect(matching).toHaveLength(present ? 1 : 0);
      if (present) {
        expect(matching[0]?.properties.value).toBe(
          "wss://example.test/review-latest",
        );
        expect(matching[0]?.evidence).toMatchObject({
          authority: "ast-static-analysis",
          state: "observed",
          confidence: "exact",
          location: {
            available: true,
            value: { kind: "source-range", source: file, start: { line: 1 } },
          },
        });
      }
    }
  } finally {
    await reader.close();
    await rm(root, { recursive: true, force: true });
  }
});
