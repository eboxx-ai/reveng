import { describe, expect, it } from "vitest";

import { webPageInspectionSchema } from "./browserObservationSchemas.js";
import { analyzeJavaScriptStaticSource } from "./javascript/javascriptStaticAnalysis.js";
import { analyzeCapturedWebBundle } from "./webBundleAnalyzer.js";
import { webBundleAnalysisSchema } from "./webBundleAnalysis.js";
import { createWebTextArtifact } from "./webContentArtifact.js";

const origin = "https://app.example.test";

it("retains standalone GraphQL Source operations in captured scripts", () => {
  const result = analyzeCapturedWebBundle(
    inspection(`
    const source = {
      body: "query GetUser { user { id } }",
      locationOffset: { line: 1, column: 1 },
    };
  `),
  );
  expect(result.observations.endpoints).toEqual([
    expect.objectContaining({ value: "GetUser", mechanism: "graphql:query" }),
  ]);
});

it.each([
  {
    kind: "recovered",
    source: "function legacy(a, a) { return a; } fetch('/partial');",
    parsed: 2,
    failures: 0,
    reason: "recovered",
    endpoints: ["/partial", "/complete"],
  },
  {
    kind: "failed",
    source: "function broken( {",
    parsed: 1,
    failures: 1,
    reason: "could not be parsed",
    endpoints: ["/complete"],
  },
])(
  "attributes $kind parse uncertainty only to its affected source",
  ({ source, parsed, failures, reason, endpoints }) => {
    const captured = inspection(source);
    const good = inspection("fetch('/complete');").scripts.items[0];
    if (good === undefined) throw new Error("Missing valid script fixture");
    captured.scripts.items.push({ ...good, script_key: "valid-script" });
    captured.scripts.total += 1;
    const result = analyzeCapturedWebBundle(captured);
    expect(result.completeness).toMatchObject({
      status: "partial",
      parsed_scripts: parsed,
      parse_failures: failures,
    });
    expect(result.unknowns).toContainEqual({
      dimension: "javascript_ast",
      reason: expect.stringContaining(reason),
      affected_script_keys: [captured.scripts.items[0]?.script_key],
    });
    expect(result.observations.endpoints.map(({ value }) => value)).toEqual(
      endpoints,
    );
  },
);

describe("web bundle analyzer", () => {
  it("extracts graph, route, endpoint, vendor, and WebMCP evidence", () => {
    const source = `
      import { createApp } from "./chunk.js?token=secret";
      const lazy = import("./lazy.js");
      const routes = [{ path: "/users/:id?token=secret" }];
      fetch("/api/users?authorization=secret");
      document.modelContext.registerTool({
        name: "lookup-user",
        description: "Untrusted page declaration",
        inputSchema: {
          type: "object",
          properties: {
            userId: { type: "string" },
            verbose: { type: "boolean" }
          }
        }
      });
      const __webpack_require__ = () => createApp(routes, lazy);
    `;
    const result = analyzeCapturedWebBundle(inspection(source));

    expect(result.observations.chunks.edges).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "static_import",
          specifier: "./chunk.js?token=secret",
          resolved_url: `${origin}/assets/chunk.js?token=secret`,
        }),
        expect.objectContaining({
          kind: "dynamic_import",
          specifier: "./lazy.js",
        }),
      ]),
    );
    expect(result.observations.routes).toEqual([
      expect.objectContaining({ value: "/users/:id?token=secret" }),
    ]);
    expect(result.observations.endpoints).toEqual([
      expect.objectContaining({
        value: "/api/users?authorization=secret",
      }),
    ]);
    expect(result.observations.webmcp_declarations).toEqual([
      expect.objectContaining({
        name: "lookup-user",
        trust: "page-declared-untrusted",
        schema_property_names: ["userId", "verbose"],
      }),
    ]);
    expect(result.inferences).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ value: "webpack", confidence: "high" }),
        expect.objectContaining({ value: "Vue" }),
      ]),
    );
    expect(JSON.stringify(result)).toContain("authorization=secret");
    expect(result.completeness.status).toBe("complete");
  });

  it("reports parser gaps without imposing a finding cap", () => {
    const malformed = inspection("function broken( {");
    const failed = analyzeCapturedWebBundle(malformed);
    expect(failed.completeness).toMatchObject({
      status: "partial",
      parse_failures: 1,
    });
    expect(failed.unknowns[0]?.dimension).toBe("javascript_ast");

    const analyzed = analyzeCapturedWebBundle(
      inspection("fetch('/one'); fetch('/two'); fetch('/three');"),
    );
    expect(analyzed.observations.endpoints).toHaveLength(3);
    expect(analyzed.completeness.status).toBe("complete");
  });

  it("analyzes AST nodes after the former fixed node ceiling", () => {
    const source = `${";".repeat(250_001)}fetch('/last');`;
    const result = analyzeCapturedWebBundle(inspection(source));

    expect(result.observations.endpoints).toContainEqual(
      expect.objectContaining({ value: "/last" }),
    );
    expect(result.completeness.visited_ast_nodes).toBeGreaterThan(250_000);
    expect(result.completeness.status).toBe("complete");
  });

  it("retains complete long chunk and WebMCP declaration text", () => {
    const specifier = `./${"chunk".repeat(1_000)}.js`;
    const name = "tool".repeat(100);
    const description = "untrusted declaration ".repeat(150);
    const propertyName = "property".repeat(100);
    const result = analyzeCapturedWebBundle(
      inspection(`
        import "${specifier}";
        document.modelContext.registerTool({
          name: "${name}",
          description: "${description}",
          inputSchema: { properties: { "${propertyName}": { type: "string" } } }
        });
      `),
    );

    expect(result.observations.chunks.edges[0]?.specifier).toBe(specifier);
    expect(result.observations.webmcp_declarations[0]).toMatchObject({
      name,
      description,
      schema_property_names: [propertyName],
      trust: "page-declared-untrusted",
    });
  });
});

describe("web bundle source-map coverage", () => {
  it("reports unavailable source maps as partial without dropping requested maps", () => {
    const analysis = analyzeCapturedWebBundle(inspection("export {};"), {
      status: "unavailable",
      requested: 1,
      processed: 1,
      items: [
        {
          script_key: `scr_${"1".repeat(64)}`,
          declared_url: "https://app.example.test/app.js.map",
          effective_url: null,
          status: "fetch_failed",
          artifact: null,
          original_sources: [],
          original_module_edges: [],
          mappings: [],
          limitation: "Source-map fetch failed.",
        },
      ],
    });

    expect(analysis.completeness.status).toBe("partial");
    expect(analysis.unknowns).toContainEqual({
      dimension: "source_maps",
      reason:
        "One or more requested source maps were unavailable or incomplete",
      affected_script_keys: [`scr_${"1".repeat(64)}`],
    });
  });

  it("keeps map-less captured source complete when no maps were requested", () => {
    const analysis = analyzeCapturedWebBundle(inspection("export {};"), {
      status: "not_requested",
      requested: 0,
      processed: 0,
      items: [],
    });

    expect(analysis.completeness.status).toBe("complete");
    expect(analysis.unknowns).toEqual([]);
  });

  it("rejects inconsistent source-map coverage counts", () => {
    const result = analyzeCapturedWebBundle(inspection("export {};"));
    expect(
      webBundleAnalysisSchema.safeParse({
        ...result,
        observations: {
          ...result.observations,
          source_maps: {
            ...result.observations.source_maps,
            requested: 1,
          },
        },
      }).success,
    ).toBe(false);
  });
});

describe("web bundle static-analysis parity", () => {
  it("recognizes endpoints through nested dynamic receivers like static analysis", () => {
    const result = analyzeCapturedWebBundle(
      inspection('window[recv].fetch("/nested-fetch");'),
    );
    expect(result.observations.endpoints).toContainEqual(
      expect.objectContaining({ value: "/nested-fetch" }),
    );
  });

  it("reads open endpoints only from XMLHttpRequest method and URL pairs", () => {
    const result = analyzeCapturedWebBundle(
      inspection(`
        xhr.open("GET", "/xhr-get");
        xhr.open("post", "https://xhr.example.test/submit");
        dav.open("PROPFIND", "/dav/");
        fs.open("/tmp/data.txt", "r", done);
        window.open("https://help.example.test/", "_blank");
        xhr.open(method, "/dynamic-method");
        fs.open(path, "r", done);
        window.open(url, "_blank");
        window.open(url, "/preview");
        globalThis.open(url, "./frame");
        document.open("text/html", "/replace");
        parent.open("GET", "/parent-xhr");
        self.open("post", "/self-xhr");
        top.open("GET", "/top-target");
        opener.open("GET", "/opener-target");
        frames.open("GET", "/frames-target");
        globalThis.open("GET", "/global-target");
        document.open("GET", "/document-target");
        const parentWindow = parent;
        parentWindow.open("GET", "/alias-target");
        {
          const parent = new XMLHttpRequest();
          parent.open(method, "/shadowed-parent-xhr");
        }
        xhr.open(method, "api/relative");
        fs.open(path, "w+", done);
        popup.open(url, "_TOP");
      `),
    );
    expect(
      result.observations.endpoints.map(({ value }) => value).sort(),
    ).toEqual([
      "/dav/",
      "/dynamic-method",
      "/shadowed-parent-xhr",
      "/xhr-get",
      "https://xhr.example.test/submit",
    ]);
    expect(result.inferences).toContainEqual(
      expect.objectContaining({
        kind: "endpoint_candidate",
        value: "api/relative",
        confidence: "low",
      }),
    );
  });
});

const socketEndpoints = (source: string) => {
  const analysis = analyzeJavaScriptStaticSource(source);
  expect(analysis.parse_status).not.toBe("failed");
  const staticEndpoints = analysis.endpoints;
  const capturedEndpoints = analyzeCapturedWebBundle(inspection(source))
    .observations.endpoints;
  return [staticEndpoints, capturedEndpoints].map((items) =>
    items.map(({ value, mechanism }) => ({ value, mechanism })),
  );
};

describe("web bundle WebSocket endpoint identity", () => {
  it("retains qualified global WebSocket URLs through both source consumers", () => {
    const source = `
      new WebSocket("wss://example.test/bare");
      new window.WebSocket("wss://example.test/window");
      new self.WebSocket("wss://example.test/self");
      new global.WebSocket("wss://example.test/node-global");
      new globalThis.WebSocket("wss://example.test/global");
      new globalThis["WebSocket"]("wss://example.test/computed");
      new globalThis[\`WebSocket\`]("wss://example.test/template");
      new globalThis.\\u0057ebSocket("wss://example.test/escaped");
    `;
    const expected = [
      ["bare", "WebSocket"],
      ["window", "window.WebSocket"],
      ["self", "self.WebSocket"],
      ["node-global", "global.WebSocket"],
      ["global", "globalThis.WebSocket"],
      ["computed", "globalThis.WebSocket"],
      ["template", "globalThis.WebSocket"],
      ["escaped", "globalThis.WebSocket"],
    ].map(([path, constructor]) => ({
      value: `wss://example.test/${path}`,
      mechanism: `call:${constructor}`,
    }));
    expect(socketEndpoints(source)).toEqual([expected, expected]);
  });

  it("does not turn shadowed or local constructors into network endpoints", () => {
    const source = `
      function local(WebSocket, window, self, globalThis) {
        new WebSocket("wss://example.test/shadowed-bare");
        new window.WebSocket("wss://example.test/shadowed-window");
        new self.WebSocket("wss://example.test/shadowed-self");
        new globalThis.WebSocket("wss://example.test/shadowed-global");
      }
      const factory = { WebSocket: class {} };
      new factory.WebSocket("wss://example.test/lookalike");
      new globalThis.WebSocket("wss://example.test/control");
    `;
    const expected = [
      {
        value: "wss://example.test/control",
        mechanism: "call:globalThis.WebSocket",
      },
    ];
    expect(socketEndpoints(source)).toEqual([expected, expected]);
  });

  it.each([
    "WebSocket = replacement;",
    "globalThis.WebSocket = replacement;",
    "const root = window; root.WebSocket = replacement;",
    "delete self.WebSocket;",
    'Object.defineProperty(globalThis, "WebSocket", { value: replacement });',
    'const root = globalThis; Reflect.set(root, "WebSocket", replacement);',
    "globalThis[key] = replacement;",
  ])("does not assert a global socket endpoint after %s", (write) => {
    expect(
      socketEndpoints(`
        ${write}
        new WebSocket("wss://example.test/bare");
        new window.WebSocket("wss://example.test/window");
        new self.WebSocket("wss://example.test/self");
        new globalThis.WebSocket("wss://example.test/global");
      `),
    ).toEqual([[], []]);
  });

  it("keeps namespace replacement distinct from constructor replacement", () => {
    const source = `
      window = replacement;
      new window.WebSocket("wss://example.test/replaced-window");
      new globalThis.WebSocket("wss://example.test/control");
    `;
    const expected = [
      {
        value: "wss://example.test/control",
        mechanism: "call:globalThis.WebSocket",
      },
    ];
    expect(socketEndpoints(source)).toEqual([expected, expected]);
  });

  it("keeps a later visible constructor write conservative rather than proving runtime order", () => {
    expect(
      socketEndpoints(`
        new globalThis.WebSocket("wss://example.test/before-write");
        globalThis.WebSocket = replacement;
      `),
    ).toEqual([[], []]);
  });

  it("preserves sockets after unrelated writes and writes to a local namespace", () => {
    const source = `
      globalThis.unrelated = replacement;
      function local(window) { window.WebSocket = replacement; }
      new window.WebSocket("wss://example.test/control");
    `;
    const expected = [
      {
        value: "wss://example.test/control",
        mechanism: "call:window.WebSocket",
      },
    ];
    expect(socketEndpoints(source)).toEqual([expected, expected]);
  });
});

describe("web bundle bound WebSocket constructors", () => {
  it.each([
    [
      'const WebSocket = globalThis.WebSocket; new WebSocket("wss://example.test/bound");',
      "WebSocket",
    ],
    [
      'const Captured = window.WebSocket; const Socket = Captured; new Socket("wss://example.test/bound");',
      "Socket",
    ],
    [
      'import WebSocket from "ws"; new WebSocket("wss://example.test/bound");',
      "WebSocket",
    ],
    [
      'import { WebSocket as Socket } from "ws"; new Socket("wss://example.test/bound");',
      "Socket",
    ],
    [
      'import * as ws from "ws"; new ws[`WebSocket`]("wss://example.test/bound");',
      "ws.WebSocket",
    ],
    [
      'import Imported from "ws"; const Socket = Imported; new Socket("wss://example.test/bound");',
      "Socket",
    ],
    [
      'const WebSocket = require("ws"); new WebSocket("wss://example.test/bound");',
      "WebSocket",
    ],
    [
      'import WebSocket = require("ws"); new WebSocket("wss://example.test/bound");',
      "WebSocket",
    ],
    [
      'const Imported = require("ws"); const Socket = Imported; new Socket("wss://example.test/bound");',
      "Socket",
    ],
    [
      'const { WebSocket: Socket } = require("ws"); new Socket("wss://example.test/bound");',
      "Socket",
    ],
    [
      'const Socket = require("ws").WebSocket; new Socket("wss://example.test/bound");',
      "Socket",
    ],
    [
      'const { WebSocket } = globalThis; new WebSocket("wss://example.test/bound");',
      "WebSocket",
    ],
    [
      'const { [`WebSocket`]: Socket } = window; new Socket("wss://example.test/bound");',
      "Socket",
    ],
    [
      'function connect() { new WebSocket("wss://example.test/bound"); } const WebSocket = globalThis.WebSocket; connect();',
      "WebSocket",
    ],
    [
      'const connect = () => new Socket("wss://example.test/bound"); const { WebSocket: Socket } = globalThis; connect();',
      "Socket",
    ],
    [
      'const connect = (function () { new Socket("wss://example.test/bound"); }).bind(null); const Socket = globalThis.WebSocket; connect();',
      "Socket",
    ],
  ])(
    "retains a proven constructor binding in both consumers: %s",
    (source, name) => {
      const expected = [
        { value: "wss://example.test/bound", mechanism: `call:${name}` },
      ];
      expect(socketEndpoints(source)).toEqual([expected, expected]);
    },
  );

  it.each([
    'const WebSocket = class {}; new WebSocket("wss://example.test/local");',
    'import WebSocket from "other-library"; new WebSocket("wss://example.test/local");',
    'import type WebSocket from "ws"; new WebSocket("wss://example.test/local");',
    'import { type WebSocket } from "ws"; new WebSocket("wss://example.test/local");',
    'let Socket = globalThis.WebSocket; Socket = replacement; new Socket("wss://example.test/local");',
    'import WebSocket from "ws"; WebSocket = replacement; new WebSocket("wss://example.test/local");',
    'new WebSocket("wss://example.test/local"); const WebSocket = globalThis.WebSocket;',
    'const WebSocket = Socket; const Socket = WebSocket; new Socket("wss://example.test/local");',
    'if (condition) { var WebSocket = globalThis.WebSocket; } new WebSocket("wss://example.test/local");',
    'function local(globalThis) { const WebSocket = globalThis.WebSocket; new WebSocket("wss://example.test/local"); }',
    'const Socket = globalThis.WebSocket; new Socket("wss://example.test/local"); globalThis.WebSocket = replacement;',
    'import Socket from "ws"; Socket.WebSocket = replacement; new Socket.WebSocket("wss://example.test/local");',
    'function local(require) { const WebSocket = require("ws"); new WebSocket("wss://example.test/local"); }',
    'const WebSocket = require("ws"); WebSocket = replacement; new WebSocket("wss://example.test/local");',
    'const Socket = require("ws").Server; new Socket("wss://example.test/local");',
    'const { default: Socket } = require("ws"); new Socket("wss://example.test/local");',
    'const Socket = require("other-library").WebSocket; new Socket("wss://example.test/local");',
    'import type WebSocket = require("ws"); new WebSocket("wss://example.test/local");',
    'const { [key]: WebSocket } = globalThis; new WebSocket("wss://example.test/local");',
    'const { WebSocket = replacement } = globalThis; new WebSocket("wss://example.test/local");',
    'const { WebSocket } = globalThis; globalThis.WebSocket = replacement; new WebSocket("wss://example.test/local");',
    '(function connect() { new WebSocket("wss://example.test/local"); })(); const WebSocket = globalThis.WebSocket;',
    'new (function () { new Socket("wss://probe.test/new"); })(); const Socket = globalThis.WebSocket;',
    '(function () { new Socket("wss://probe.test/call"); }).call(null); const Socket = globalThis.WebSocket;',
    '(function () { new Socket("wss://probe.test/apply"); }).apply(null, []); const Socket = globalThis.WebSocket;',
    'new WebSocket("wss://example.test/local"); import WebSocket = require("ws");',
  ])(
    "does not infer constructor identity from an unresolved binding: %s",
    (source) => {
      expect(socketEndpoints(source)).toEqual([[], []]);
    },
  );
});

describe("web bundle WebSocket execution phases", () => {
  it.each([
    '(function () { new Socket("wss://example.test/eager"); } as any)();',
    '(function () { new Socket("wss://example.test/eager"); })!();',
    '(function () { new Socket("wss://example.test/eager"); } satisfies Function).call(null);',
    '(function () { new Socket("wss://example.test/eager"); }).bind(null)();',
    'new ((function () { new Socket("wss://example.test/eager"); }).bind(null))();',
    '(function* (x = new Socket("wss://example.test/eager")) {})();',
    '(function* (x = new Socket("wss://example.test/eager")) {}).call(null);',
    '(function* (x = new Socket("wss://example.test/eager")) {}).apply(null, []);',
    'class Client { static socket = new Socket("wss://example.test/eager"); }',
    'class Client { [new Socket("wss://example.test/eager")] = 1; }',
    '(async () => { new Socket("wss://example.test/eager"); await ready; })();',
    '(async () => { new Socket("wss://example.test/eager", await ready); })();',
    '(async () => { if (condition) await ready; new Socket("wss://example.test/eager"); })();',
    '(async () => { const later = async () => { await ready; }; new Socket("wss://example.test/eager"); })();',
  ])("excludes an eager capture before initialization: %s", (expression) => {
    expect(
      socketEndpoints(`${expression} const Socket = globalThis.WebSocket;`),
    ).toEqual([[], []]);
  });

  it.each([
    'class Client { socket = new Socket("wss://example.test/deferred"); }',
    'class Client { #socket = new Socket("wss://example.test/deferred"); }',
    '(function* () { new Socket("wss://example.test/deferred"); })();',
    '(async () => { await ready; new Socket("wss://example.test/deferred"); })();',
    '(async () => { const value = await ready; new Socket("wss://example.test/deferred"); })();',
    '(async () => { (await ready, new Socket("wss://example.test/deferred")); })();',
    'const connect = (function () { new Socket("wss://example.test/deferred"); } as any).bind(null);',
  ])("retains a deferred capture of the later binding: %s", (expression) => {
    const expected = [
      { value: "wss://example.test/deferred", mechanism: "call:Socket" },
    ];
    expect(
      socketEndpoints(`${expression} const Socket = globalThis.WebSocket;`),
    ).toEqual([expected, expected]);
  });

  it.each([
    '(async () => { await ready; new Socket("wss://example.test/tdz"); const Socket = globalThis.WebSocket; })();',
    '(async () => { new Socket("wss://example.test/tdz"); await ready; const Socket = globalThis.WebSocket; })();',
    '(async () => { await ready; new Socket("wss://example.test/tdz"); await ready; const Socket = globalThis.WebSocket; })();',
    '(async () => { (() => { new Socket("wss://example.test/tdz"); })(); await ready; const Socket = globalThis.WebSocket; })();',
  ])(
    "preserves initializer ordering across awaits in a shared frame: %s",
    (source) => {
      expect(socketEndpoints(source)).toEqual([[], []]);
    },
  );

  it.each([
    'new (class { socket = new Socket("wss://example.test/tdz"); })();',
    'new (class { #socket = new Socket("wss://example.test/tdz"); })();',
    'new ((class { socket = new Socket("wss://example.test/tdz"); } as any).bind(null))();',
    'new (class { constructor() { new Socket("wss://example.test/tdz"); } })();',
  ])(
    "keeps immediately constructed class initialization eager: %s",
    (expression) => {
      expect(
        socketEndpoints(`${expression} const Socket = globalThis.WebSocket;`),
      ).toEqual([[], []]);
    },
  );

  it.each([
    'const Socket = globalThis.WebSocket; new (class { socket = new Socket("wss://example.test/class"); })();',
    '(async () => { await ready; new (class { socket = new Socket("wss://example.test/class"); })(); })(); const Socket = globalThis.WebSocket;',
    'const Client = class { socket = new Socket("wss://example.test/class"); }; const Socket = globalThis.WebSocket; new Client();',
  ])("retains initialized or deferred class construction: %s", (source) => {
    const expected = [
      { value: "wss://example.test/class", mechanism: "call:Socket" },
    ];
    expect(socketEndpoints(source)).toEqual([expected, expected]);
  });
});

describe("web bundle constructor suspension order", () => {
  it.each([
    'let value; (async () => { value = await ready; new Socket("wss://example.test/resumed"); })();',
    '(async () => { (() => { new Socket("wss://example.test/resumed"); })(await ready); })();',
    '(async () => { new (class { socket = new Socket("wss://example.test/resumed"); })(await ready); })();',
    '(async () => { new (class { constructor() { new Socket("wss://example.test/resumed"); } })(await ready); })();',
    '(async () => { new (class { [await ready] = 0; socket = new Socket("wss://example.test/resumed"); })(); })();',
    '(async () => { new (class { socket = new Socket("wss://example.test/resumed"); [await ready] = 0; })(); })();',
    '(async () => { new (class { static socket = new Socket("wss://example.test/resumed"); [await ready] = 0; })(); })();',
    '(function* () { yield 0; new Socket("wss://example.test/resumed"); })().next();',
    '(async () => { (function* () { new Socket("wss://example.test/resumed"); })().next(await ready); })();',
  ])(
    "retains a constructor read after its preceding suspension: %s",
    (expression) => {
      const expected = [
        { value: "wss://example.test/resumed", mechanism: "call:Socket" },
      ];
      expect(
        socketEndpoints(`${expression} const Socket = globalThis.WebSocket;`),
      ).toEqual([expected, expected]);
    },
  );

  it.each([
    '(function* () { new Socket("wss://example.test/tdz"); })().next();',
    '(async function* () { new Socket("wss://example.test/tdz"); })().next();',
    '(function* () { new Socket("wss://example.test/tdz"); }).call(null).next();',
    '(async () => { new (class { static socket = new Socket("wss://example.test/tdz"); })(await ready); })();',
    '(async () => { new (class { [new Socket("wss://example.test/tdz")] = 0; })(await ready); })();',
    'let value; (async () => { value &&= await ready; new Socket("wss://example.test/tdz"); })();',
    '(async () => { new (class { socket = new Socket("wss://example.test/tdz"); })(await ready); const Socket = globalThis.WebSocket; })();',
  ])(
    "does not move a callee, key, or local TDZ past a later suspension: %s",
    (expression) => {
      expect(
        socketEndpoints(`${expression} const Socket = globalThis.WebSocket;`),
      ).toEqual([[], []]);
    },
  );
});

describe("web bundle CommonJS socket member mutation", () => {
  it.each([
    'const ws = require("ws"); ws.WebSocket = class {}; new ws.WebSocket("wss://example.test/local");',
    'const ws = require("ws"); const alias = ws; alias.WebSocket = class {}; new ws.WebSocket("wss://example.test/local");',
    'const ws = require("ws"); const alias = ws; ws.WebSocket = class {}; new alias.WebSocket("wss://example.test/local");',
    'const ws = require("ws"); const box = { ws }; box.ws.WebSocket = class {}; new ws.WebSocket("wss://example.test/local");',
    'require("ws").WebSocket = class {}; const ws = require("ws"); new ws.WebSocket("wss://example.test/local");',
    'const ws = require("ws"); ws.WebSocket = class {}; const Socket = ws.WebSocket; new Socket("wss://example.test/local");',
    'const ws = require("ws"); ws.WebSocket = class {}; const { WebSocket: Socket } = ws; new Socket("wss://example.test/local");',
    'const ws = require("ws"); Object.defineProperty(ws, "WebSocket", { value: class {} }); new ws.WebSocket("wss://example.test/local");',
    'const ws = require("ws"); const set = Reflect.set; set(ws, "WebSocket", class {}); new ws.WebSocket("wss://example.test/local");',
    'const ws = require("ws"); ws[key] = class {}; new ws.WebSocket("wss://example.test/local");',
    'const ws = require("ws"); const alias = ws[key]; alias.WebSocket = class {}; new ws.WebSocket("wss://example.test/local");',
    'const ws = require("ws"); const { WebSocket: alias } = ws; alias.WebSocket = class {}; new ws.WebSocket("wss://example.test/local");',
    'const ws = require("ws"); delete ws.WebSocket; new ws.WebSocket("wss://example.test/local");',
  ])("excludes a visibly replaced selected export: %s", (source) => {
    expect(socketEndpoints(source)).toEqual([[], []]);
  });

  it.each([
    'const ws = require("ws"); const Socket = ws.WebSocket; ws.WebSocket = class {}; new Socket("wss://example.test/intact");',
    'const ws = require("ws"); new ws.WebSocket("wss://example.test/intact"); ws.WebSocket = class {};',
    'const ws = require("ws"); ws.Server = class {}; new ws.WebSocket("wss://example.test/intact");',
    'const ws = require("ws"); ws.WebSocket = class {}; new ws("wss://example.test/intact");',
    'const ws = require("ws"); const Socket = ws.WebSocket; Socket.WebSocket = class {}; new Socket("wss://example.test/intact");',
    'const ws = require("ws"); let alias = ws; alias = {}; alias.WebSocket = class {}; new ws.WebSocket("wss://example.test/intact");',
    'const ws = require("ws"); const copy = { ...ws }; copy.WebSocket = class {}; new ws.WebSocket("wss://example.test/intact");',
    'const ws = require("ws"); const { WebSocket: Socket } = ws; ws.WebSocket = class {}; new Socket("wss://example.test/intact");',
  ])(
    "retains a constructor captured before replacement or an untouched slot: %s",
    (source) => {
      const result = socketEndpoints(source);
      expect(result[0]?.map(({ value }) => value)).toEqual([
        "wss://example.test/intact",
      ]);
      expect(result[1]?.map(({ value }) => value)).toEqual([
        "wss://example.test/intact",
      ]);
    },
  );
});

describe("web bundle conditional suspension and sequence invocations", () => {
  it.each([
    '(async () => { if (await ready) new Socket("wss://example.test/branch"); })();',
    '(async () => { if (await ready) {} else new Socket("wss://example.test/branch"); })();',
    '(async () => { if (await ready) {} new Socket("wss://example.test/branch"); })();',
    '(async () => { (await ready) ? new Socket("wss://example.test/branch") : 0; })();',
    '(async () => { (await ready) && new Socket("wss://example.test/branch"); })();',
  ])(
    "retains branch reads after an evaluated test suspension: %s",
    (expression) => {
      const expected = [
        { value: "wss://example.test/branch", mechanism: "call:Socket" },
      ];
      expect(
        socketEndpoints(`${expression} const Socket = globalThis.WebSocket;`),
      ).toEqual([expected, expected]);
    },
  );

  it.each([
    '(0, function () { new Socket("wss://example.test/tdz"); })();',
    '((0, function () { new Socket("wss://example.test/tdz"); }) as any)();',
    '(0, () => { new Socket("wss://example.test/tdz"); })();',
    '(0, function () { new Socket("wss://example.test/tdz"); }).call(null);',
    'new (0, class { socket = new Socket("wss://example.test/tdz"); })();',
    '(0, function* () { new Socket("wss://example.test/tdz"); })().next();',
    '(async () => { if (condition) await ready; new Socket("wss://example.test/tdz"); })();',
    '(async () => { condition && (await ready); new Socket("wss://example.test/tdz"); })();',
  ])(
    "keeps immediate final operands eager without assuming skipped branch suspension: %s",
    (expression) => {
      expect(
        socketEndpoints(`${expression} const Socket = globalThis.WebSocket;`),
      ).toEqual([[], []]);
    },
  );

  it("retains a stored final-operand constructor capture", () => {
    const expected = [
      { value: "wss://example.test/stored-sequence", mechanism: "call:Socket" },
    ];
    expect(
      socketEndpoints(
        'const connect = (0, function () { new Socket("wss://example.test/stored-sequence"); }); const Socket = globalThis.WebSocket; connect();',
      ),
    ).toEqual([expected, expected]);
  });
});

describe("web bundle evaluated socket continuations", () => {
  it.each([
    '(async () => { while (await ready) { new Socket("wss://example.test/resumed"); break; } })();',
    '(async () => { for (; await ready;) { new Socket("wss://example.test/resumed"); break; } })();',
    '(async () => { [await ready, new Socket("wss://example.test/resumed")]; })();',
    '(async () => { [,[...(await ready)], new Socket("wss://example.test/resumed")]; })();',
    '(async () => { while (await ready) {} new Socket("wss://example.test/resumed"); })();',
    '(async function* () { yield* []; new Socket("wss://example.test/resumed"); })().next();',
    '(function* () { yield; new Socket("wss://example.test/resumed"); })().next();',
    '(async () => { await (async () => { await ready; new Socket("wss://example.test/resumed"); })(); })();',
  ])(
    "retains a read after its mandatory evaluation prefix: %s",
    (expression) => {
      const expected = [
        { value: "wss://example.test/resumed", mechanism: "call:Socket" },
      ];
      expect(
        socketEndpoints(`${expression} const Socket = globalThis.WebSocket;`),
      ).toEqual([expected, expected]);
    },
  );

  it.each([
    '(function* () { yield* []; new Socket("wss://example.test/tdz"); })().next(); const Socket = globalThis.WebSocket;',
    '(function* () { yield* values; new Socket("wss://example.test/tdz"); })().next(); const Socket = globalThis.WebSocket;',
    '(async () => { do { new Socket("wss://example.test/tdz"); } while (await ready); })(); const Socket = globalThis.WebSocket;',
    '(async () => { while (condition) await ready; new Socket("wss://example.test/tdz"); })(); const Socket = globalThis.WebSocket;',
    '(async () => { [new Socket("wss://example.test/tdz"), await ready]; })(); const Socket = globalThis.WebSocket;',
    '(async () => { await (async () => { await ready; new Socket("wss://example.test/tdz"); })(); const Socket = globalThis.WebSocket; })();',
    '(async () => { await (async () => { await (async () => { await ready; new Socket("wss://example.test/tdz"); })(); })(); const Socket = globalThis.WebSocket; })();',
    '(async () => { while (await ready) { new Socket("wss://example.test/tdz"); const Socket = globalThis.WebSocket; } })();',
  ])(
    "does not turn conditional suspension or a waiting initializer into identity: %s",
    (source) => {
      expect(socketEndpoints(source)).toEqual([[], []]);
    },
  );
});

describe("web bundle exact constructor result values", () => {
  it.each([
    "const Socket = (0, globalThis.WebSocket);",
    "const Socket = (0, (1, globalThis.WebSocket));",
    "const Socket = (0, globalThis).WebSocket;",
  ])("follows only a sequence's resulting value: %s", (capture) => {
    const expected = [
      { value: "wss://example.test/result", mechanism: "call:Socket" },
    ];
    expect(
      socketEndpoints(`${capture} new Socket("wss://example.test/result");`),
    ).toEqual([expected, expected]);
  });

  it.each([
    'const Socket = (globalThis.WebSocket, class {}); new Socket("wss://example.test/invalid");',
    'switch (kind) { case 0: const Socket = globalThis.WebSocket; break; case 1: new Socket("wss://example.test/invalid"); }',
  ])("rejects skipped or discarded constructor values: %s", (source) => {
    expect(socketEndpoints(source)).toEqual([[], []]);
  });
});

it("retains a constructor initialized in the same selected switch case", () => {
  const expected = [
    { value: "wss://example.test/result", mechanism: "call:Socket" },
  ];
  expect(
    socketEndpoints(
      'switch (kind) { case 0: const Socket = globalThis.WebSocket; new Socket("wss://example.test/result"); break; }',
    ),
  ).toEqual([expected, expected]);
});

describe("web bundle literal dynamic socket imports", () => {
  it.each([
    'const { WebSocket: Socket } = await import("ws");',
    'const { default: Socket } = await import("ws");',
    'const ws = await import("ws"); const Socket = ws.WebSocket;',
    'const Socket = (await import("ws")).WebSocket;',
  ])("retains an exact awaited module export: %s", (capture) => {
    const expected = [
      { value: "wss://example.test/imported", mechanism: "call:Socket" },
    ];
    expect(
      socketEndpoints(`${capture} new Socket("wss://example.test/imported");`),
    ).toEqual([expected, expected]);
  });

  it.each([
    'const { WebSocket: Socket } = import("ws");',
    "const { WebSocket: Socket } = await import(name);",
    'const { WebSocket: Socket } = await import("other");',
    'const { Server: Socket } = await import("ws");',
    'const Socket = (await import("ws")).default.WebSocket;',
    'let { WebSocket: Socket } = await import("ws"); Socket = class {};',
  ])(
    "does not infer promise values or unresolved module exports: %s",
    (capture) => {
      expect(
        socketEndpoints(`${capture} new Socket("wss://example.test/invalid");`),
      ).toEqual([[], []]);
    },
  );
});

describe("web bundle promise aliases and object evaluation", () => {
  it.each([
    '({ first: await ready, second: new Socket("wss://example.test/object") });',
    '({ [await ready]: new Socket("wss://example.test/object") });',
    '({ [await ready]: 0, second: new Socket("wss://example.test/object") });',
    '({ ...(await ready), second: new Socket("wss://example.test/object") });',
    '({ [await ready]() {}, second: new Socket("wss://example.test/object") });',
    '({ first: { nested: await ready }, second: new Socket("wss://example.test/object") });',
  ])(
    "carries completed property evaluation into later values: %s",
    (expression) => {
      const expected = [
        { value: "wss://example.test/object", mechanism: "call:Socket" },
      ];
      expect(
        socketEndpoints(
          `(async () => { ${expression} })(); const Socket = globalThis.WebSocket;`,
        ),
      ).toEqual([expected, expected]);
    },
  );

  it.each([
    '({ first: new Socket("wss://example.test/invalid"), second: await ready });',
    '({ async method() { await ready; }, second: new Socket("wss://example.test/invalid") });',
    '({ first: condition && (await ready), second: new Socket("wss://example.test/invalid") });',
  ])(
    "does not promote later, deferred or skipped property awaits: %s",
    (expression) => {
      expect(
        socketEndpoints(
          `(async () => { ${expression} })(); const Socket = globalThis.WebSocket;`,
        ),
      ).toEqual([[], []]);
    },
  );

  it.each([
    'const pending = (async () => { await ready; new Socket("wss://example.test/invalid"); })(); await pending; const Socket = globalThis.WebSocket;',
    'const pending = (async () => { await ready; new Socket("wss://example.test/invalid"); })(); const alias = pending; await alias; const Socket = globalThis.WebSocket;',
    '(async () => { const pending = (async () => { await ready; new Socket("wss://example.test/invalid"); })(); await pending; const Socket = globalThis.WebSocket; })();',
    'const pending = (async () => { await ready; new Socket("wss://example.test/invalid"); })(); await pending; await pending; const Socket = globalThis.WebSocket;',
  ])(
    "retains the actual wait point of a stable promise result: %s",
    (source) => {
      expect(socketEndpoints(source)).toEqual([[], []]);
    },
  );

  it.each([
    'const pending = (async () => { await ready; new Socket("wss://example.test/wait"); })(); const Socket = globalThis.WebSocket; await pending;',
    'const pending = (async () => { await ready; new Socket("wss://example.test/wait"); })(); const alias = pending; const Socket = globalThis.WebSocket; await alias;',
    '(async () => { const pending = (async () => { await ready; new Socket("wss://example.test/wait"); })(); const Socket = globalThis.WebSocket; await pending; })();',
    'const pending = (async () => { await ready; new Socket("wss://example.test/wait"); })(); (async (pending) => { await pending; })(ready); const Socket = globalThis.WebSocket;',
  ])(
    "keeps initialization before a wait distinct from promise creation: %s",
    (source) => {
      const expected = [
        { value: "wss://example.test/wait", mechanism: "call:Socket" },
      ];
      expect(socketEndpoints(source)).toEqual([expected, expected]);
    },
  );

  it.each([
    'const pending = import("ws"); const { WebSocket: Socket } = await pending;',
    'const pending = import("ws"); const alias = pending; const { default: Socket } = await alias;',
    "const pending = import(`ws`); const Socket = (await pending).WebSocket;",
  ])(
    "retains a literal module through its stable pending promise: %s",
    (capture) => {
      const expected = [
        { value: "wss://example.test/import-alias", mechanism: "call:Socket" },
      ];
      expect(
        socketEndpoints(
          `${capture} new Socket("wss://example.test/import-alias");`,
        ),
      ).toEqual([expected, expected]);
    },
  );

  it.each([
    'let pending = import("ws"); pending = import("other"); const { WebSocket: Socket } = await pending;',
    'const pending = import("other"); const { WebSocket: Socket } = await pending;',
    "const pending = other; const other = pending; const { WebSocket: Socket } = await pending;",
    'const { WebSocket: Socket } = await pending; const pending = import("ws");',
    'const box = { pending: import("ws") }; const { WebSocket: Socket } = await box.pending;',
  ])(
    "leaves unstable, forward and unproven promise identities unresolved: %s",
    (capture) => {
      expect(
        socketEndpoints(`${capture} new Socket("wss://example.test/invalid");`),
      ).toEqual([[], []]);
    },
  );
});

describe("web bundle selected invocations, imports and case waits", () => {
  it.each([
    '(true ? () => new Socket("wss://example.test/invalid") : noop)(); const Socket = globalThis.WebSocket;',
    '(false ? noop : function () { new Socket("wss://example.test/invalid"); })(); const Socket = globalThis.WebSocket;',
    '(true && (() => new Socket("wss://example.test/invalid")))(); const Socket = globalThis.WebSocket;',
    '(false || function () { new Socket("wss://example.test/invalid"); })(); const Socket = globalThis.WebSocket;',
    '(null ?? function () { new Socket("wss://example.test/invalid"); })(); const Socket = globalThis.WebSocket;',
    '({ run() { new Socket("wss://example.test/invalid"); } }).run(); const Socket = globalThis.WebSocket;',
    '({ [`run`]() { new Socket("wss://example.test/invalid"); } })[`run`](); const Socket = globalThis.WebSocket;',
    '({ run: () => new Socket("wss://example.test/invalid") }).run(); const Socket = globalThis.WebSocket;',
    '({ run() { new Socket("wss://example.test/invalid"); } }).run.call(null); const Socket = globalThis.WebSocket;',
    '({ run() { new Socket("wss://example.test/invalid"); } }).run.bind(null)(); const Socket = globalThis.WebSocket;',
    '(true ? { run() { new Socket("wss://example.test/invalid"); } } : other).run(); const Socket = globalThis.WebSocket;',
    '@(function () { new Socket("wss://example.test/invalid"); }) class Client {}; const Socket = globalThis.WebSocket;',
    '@(() => { new Socket("wss://example.test/invalid"); }) class Client {}; const Socket = globalThis.WebSocket;',
    'class Client { @(function () { new Socket("wss://example.test/invalid"); }) run() {} }; const Socket = globalThis.WebSocket;',
    '(async () => { switch (kind) { case 0: const pending = (async () => { await ready; new Socket("wss://example.test/invalid"); })(); await pending; } const Socket = globalThis.WebSocket; })();',
    '(async () => { switch (kind) { case 0: const pending = (async () => { await ready; new Socket("wss://example.test/invalid"); })(); const alias = pending; await alias; } const Socket = globalThis.WebSocket; })();',
    '(async () => { switch (kind) { case 0: const pending = (async () => { await ready; new Socket("wss://example.test/invalid"); })(); await (async () => { await pending; })(); } const Socket = globalThis.WebSocket; })();',
    '(async () => { import("owned:module"); new Socket("wss://example.test/invalid"); })(); const Socket = globalThis.WebSocket;',
    '(async () => { import("owned:module", { ignored: async () => await ready }); new Socket("wss://example.test/invalid"); })(); const Socket = globalThis.WebSocket;',
    'const Socket = condition ? globalThis.WebSocket : Fake; new Socket("wss://example.test/invalid");',
  ])(
    "does not manufacture a deferred activation or a mandatory wait: %s",
    (source) => {
      expect(socketEndpoints(source)).toEqual([[], []]);
    },
  );

  it.each([
    '(async () => { import(await ready); new Socket("wss://example.test/selected"); })(); const Socket = globalThis.WebSocket;',
    '(async () => { import("owned:module", await ready); new Socket("wss://example.test/selected"); })(); const Socket = globalThis.WebSocket;',
    '(async () => { import("owned:module", { with: { type: await ready } }); new Socket("wss://example.test/selected"); })(); const Socket = globalThis.WebSocket;',
    'const connect = (true ? () => new Socket("wss://example.test/selected") : noop); const Socket = globalThis.WebSocket; connect();',
    'const connect = ({ run() { new Socket("wss://example.test/selected"); } }).run; const Socket = globalThis.WebSocket; connect();',
    '({ async run() { await ready; new Socket("wss://example.test/selected"); } }).run(); const Socket = globalThis.WebSocket;',
    '@(function* () { new Socket("wss://example.test/selected"); }) class Client {}; const Socket = globalThis.WebSocket;',
    '@(function () { return function () { new Socket("wss://example.test/selected"); }; }) class Client {}; const Socket = globalThis.WebSocket; Client();',
    '(async () => { @(function () { new Socket("wss://example.test/selected"); }) class Client { [await ready]() {} } })(); const Socket = globalThis.WebSocket;',
    '(async () => { class Client { @(function () { new Socket("wss://example.test/selected"); }) run() {} [await ready]() {} } })(); const Socket = globalThis.WebSocket;',
    'const Socket = true ? globalThis.WebSocket : Fake; new Socket("wss://example.test/selected");',
    'const Socket = false || globalThis.WebSocket; new Socket("wss://example.test/selected");',
    '(async () => { switch (kind) { case 0: const pending = (async () => { await ready; new Socket("wss://example.test/selected"); })(); break; await pending; } const Socket = globalThis.WebSocket; })();',
    '(async () => { const pending = (async () => { await ready; new Socket("wss://example.test/selected"); })(); switch (kind) { case 0: await pending; } const Socket = globalThis.WebSocket; })();',
  ])(
    "retains proven selections and suspension without promoting skipped paths: %s",
    (source) => {
      expect(
        socketEndpoints(source).map((items) => items.map((item) => item.value)),
      ).toEqual([
        ["wss://example.test/selected"],
        ["wss://example.test/selected"],
      ]);
    },
  );
});

describe("web bundle selected bindings and reachable waits", () => {
  it.each([
    'const pending = (async () => { await 0; new Socket("wss://example.test/invalid"); })(); await (async () => { await pending; })(); const Socket = globalThis.WebSocket;',
    'const pending = (async () => { await 0; new Socket("wss://example.test/invalid"); })(); await (async () => { await 0; await pending; })(); const Socket = globalThis.WebSocket;',
    'const pending = (async () => { await 0; new Socket("wss://example.test/invalid"); })(); const alias = pending; await (async () => { await alias; })(); const Socket = globalThis.WebSocket;',
    'const pending = (async () => { await 0; new Socket("wss://example.test/invalid"); })(); await (async () => { await (async () => { await pending; })(); })(); const Socket = globalThis.WebSocket;',
    '(async () => { if (condition) { const pending = (async () => { await 0; new Socket("wss://example.test/invalid"); })(); await (async () => { await pending; })(); } const Socket = globalThis.WebSocket; })();',
  ])(
    "retains initialized blocking aliases through literal callers: %s",
    (source) => {
      // Declare module mode: await(f)() can also be an ordinary script call.
      expect(socketEndpoints(`export {}; ${source}`)).toEqual([[], []]);
    },
  );

  it.each([
    'const pending = (async () => { await ready; new Socket("wss://example.test/selected"); })(); await (async () => { if (condition) await pending; })(); const Socket = globalThis.WebSocket;',
    'const pending = (async () => { await ready; new Socket("wss://example.test/selected"); })(); try { await (async () => { await alias; })(); } catch {} const alias = pending; const Socket = globalThis.WebSocket;',
    'const pending = (async () => { await 0; new Socket("wss://example.test/selected"); })(); (async () => { await pending; })(); const Socket = globalThis.WebSocket;',
    '(async () => { const pending = (async () => { await 0; new Socket("wss://example.test/selected"); })(); if (condition) await (async () => { await pending; })(); const Socket = globalThis.WebSocket; })();',
  ])(
    "does not promote optional or uninitialized cross-caller waits: %s",
    (source) => {
      expect(
        socketEndpoints(`export {}; ${source}`).map((items) =>
          items.map((item) => item.value),
        ),
      ).toEqual([
        ["wss://example.test/selected"],
        ["wss://example.test/selected"],
      ]);
    },
  );

  it.each([
    'const pending = (async () => { await 0; new Socket("wss://example.test/selected"); })(); try { await alias; } catch {} const alias = pending; const Socket = globalThis.WebSocket;',
    'const pending = (async () => { await 0; new Socket("wss://example.test/selected"); })(); try { await second; } catch {} const first = pending; const second = first; const Socket = globalThis.WebSocket;',
    '(async () => { const pending = (async () => { await ready; new Socket("wss://example.test/selected"); })(); while (true) { break; await pending; } const Socket = globalThis.WebSocket; })();',
    '(async () => { const pending = (async () => { await ready; new Socket("wss://example.test/selected"); })(); for (let i = 0; i < 1; i++) { continue; await pending; } const Socket = globalThis.WebSocket; })();',
    '(async () => { (await ready).value &&= new Socket("wss://example.test/selected"); })(); const Socket = globalThis.WebSocket;',
    '(async () => { (await ready).value ||= new Socket("wss://example.test/selected"); })(); const Socket = globalThis.WebSocket;',
    '(async () => { (await ready).value ??= new Socket("wss://example.test/selected"); })(); const Socket = globalThis.WebSocket;',
    '(async () => { switch (kind) { case 0: await ready; new Socket("wss://example.test/selected"); } })(); const Socket = globalThis.WebSocket;',
    '(async () => { switch (kind) { default: 0; await ready; new Socket("wss://example.test/selected"); } })(); const Socket = globalThis.WebSocket;',
    'import ws = require("ws"); const other = require("ws"); ws = {}; ws.WebSocket = class {}; new other.WebSocket("wss://example.test/selected");',
    'import ws = require("ws"); const other = require("ws"); ws = {}; const replacement = ws; replacement.WebSocket = class {}; new other.WebSocket("wss://example.test/selected");',
    'Array.prototype[Symbol.iterator] = function* () { yield class {}; }; const { 0: Socket } = [globalThis.WebSocket]; new Socket("wss://example.test/selected");',
    'let box; const { WebSocket: Socket, unused = (box.WebSocket = class {}) } = (box = { WebSocket: globalThis.WebSocket }); new Socket("wss://example.test/selected");',
    'let box; const { 0: Socket, unused = (box.length = 0) } = (box = [globalThis.WebSocket]); new Socket("wss://example.test/selected");',
  ])("retains source-proven constructor reads: %s", (source) => {
    expect(
      socketEndpoints(source).map((items) => items.map((item) => item.value)),
    ).toEqual([
      ["wss://example.test/selected"],
      ["wss://example.test/selected"],
    ]);
  });

  it.each([
    '(async () => { if (condition) { const pending = (async () => { await ready; new Socket("wss://example.test/invalid"); })(); await pending; } const Socket = globalThis.WebSocket; })();',
    '(async () => { if (condition) { const pending = (async () => { await ready; new Socket("wss://example.test/invalid"); })(); const alias = pending; await alias; } const Socket = globalThis.WebSocket; })();',
    'let box; const { unused = (box.WebSocket = class {}), WebSocket: Socket } = (box = { WebSocket: globalThis.WebSocket }); new Socket("wss://example.test/invalid");',
    'let box; const { [box.WebSocket = class {}]: unused, WebSocket: Socket } = (box = { WebSocket: globalThis.WebSocket }); new Socket("wss://example.test/invalid");',
    'let box; const { nested: { unused = (box.nested.WebSocket = class {}), WebSocket: Socket } } = (box = { nested: { WebSocket: globalThis.WebSocket } }); new Socket("wss://example.test/invalid");',
    'let box; const { unused = (box.length = 0), 0: Socket } = (box = [globalThis.WebSocket]); new Socket("wss://example.test/invalid");',
    'Array.prototype[Symbol.iterator] = function* () { yield class {}; }; const [Socket] = [globalThis.WebSocket]; new Socket("wss://example.test/invalid");',
    'const prototype = Array.prototype; prototype[Symbol.iterator] = function* () { yield class {}; }; const [Socket] = (0, [globalThis.WebSocket]); new Socket("wss://example.test/invalid");',
    'globalThis.Array.prototype[Symbol.iterator] = function* () { yield class {}; }; const { nested: [Socket] } = { nested: [globalThis.WebSocket] }; new Socket("wss://example.test/invalid");',
    'globalThis.WebSocket("wss://example.test/invalid");',
    'const Socket = globalThis.WebSocket; Socket("wss://example.test/invalid");',
    'window[`WebSocket`]("wss://example.test/invalid");',
    '(async () => { try { using resource = 1; await 0; } finally { new Socket("wss://example.test/invalid"); } })(); const Socket = globalThis.WebSocket;',
    '(async () => { try { await using resource = 1; await 0; } finally { new Socket("wss://example.test/invalid"); } })(); const Socket = globalThis.WebSocket;',
    '(async () => { condition &&= await ready; new Socket("wss://example.test/invalid"); })(); const Socket = globalThis.WebSocket;',
    '(async () => { switch (kind) { case 0: await ready; break; case 1: new Socket("wss://example.test/invalid"); } })(); const Socket = globalThis.WebSocket;',
    'import ws = require("ws"); const other = require("ws"); ws.WebSocket = class {}; new other.WebSocket("wss://example.test/invalid");',
    '(async () => { const pending = (async () => { await ready; new Socket("wss://example.test/invalid"); })(); const alias = pending; await alias; const Socket = globalThis.WebSocket; })();',
  ])(
    "does not manufacture construction, value or wait proofs: %s",
    (source) => {
      expect(socketEndpoints(source)).toEqual([[], []]);
    },
  );
});

describe("web bundle owned waits and exact result paths", () => {
  it.each([
    '(async () => { try { await 0; } finally { new Socket("wss://example.test/owned"); } })(); const Socket = globalThis.WebSocket;',
    '(async () => { try { 1; await 0; throw 0; } finally { new Socket("wss://example.test/owned"); } })(); const Socket = globalThis.WebSocket;',
    '(async () => { try { { await 0; } } catch {} finally { new Socket("wss://example.test/owned"); } })(); const Socket = globalThis.WebSocket;',
    'const [Socket] = (0, [globalThis.WebSocket]); new Socket("wss://example.test/owned");',
    'let saved; const [Socket] = (saved = [globalThis.WebSocket]); new Socket("wss://example.test/owned");',
    'const { nested: [Socket] } = (0, { nested: (0, [globalThis.WebSocket]) }); new Socket("wss://example.test/owned");',
    'const [[Socket]] = [(0, [globalThis.WebSocket])]; new Socket("wss://example.test/owned");',
    '(async () => { switch (await ready) { default: new Socket("wss://example.test/owned"); } })(); const Socket = globalThis.WebSocket;',
    '(async () => { switch (await ready) { default: break; } new Socket("wss://example.test/owned"); })(); const Socket = globalThis.WebSocket;',
    '(async () => { (await ready)?.(new Socket("wss://example.test/owned")); })(); const Socket = globalThis.WebSocket;',
    '(async () => { (await ready)?.call(null, new Socket("wss://example.test/owned")); })(); const Socket = globalThis.WebSocket;',
    '(async () => { (await ready).count++; new Socket("wss://example.test/owned"); })(); const Socket = globalThis.WebSocket;',
    '(async () => { ++(await ready).count; new Socket("wss://example.test/owned"); })(); const Socket = globalThis.WebSocket;',
    'const ws = require("ws"); const Socket = ws.WebSocket; if (flag) { ws.WebSocket = Fake; } new Socket("wss://example.test/owned");',
    'const ws = require("ws"); const Socket = ws.WebSocket; try { ws.WebSocket = Fake; } finally {} new Socket("wss://example.test/owned");',
    'const ws = require("ws"); const Socket = ws.WebSocket; for (const value of items) { ws.WebSocket = Fake; } new Socket("wss://example.test/owned");',
    'const ws = require("ws"); const Socket = ws.WebSocket.WebSocket; new Socket("wss://example.test/owned");',
    'const Socket = require("ws").WebSocket.WebSocket.WebSocket; new Socket("wss://example.test/owned");',
    'import ws = require("ws"); const Socket = ws.WebSocket.WebSocket; new Socket("wss://example.test/owned");',
    'const ws = require("ws"); new ws.WebSocket.WebSocket("wss://example.test/owned");',
    '(async () => { const pending = (async () => { await ready; new Socket("wss://example.test/owned"); })(); if (condition) await pending; const Socket = globalThis.WebSocket; })();',
  ])(
    "retains a proven endpoint through shared producing facts: %s",
    (source) => {
      expect(
        socketEndpoints(source).map((items) => items.map((item) => item.value)),
      ).toEqual([["wss://example.test/owned"], ["wss://example.test/owned"]]);
    },
  );

  it.each([
    '(async () => { try { throw 0; await 0; } finally { new Socket("wss://example.test/invalid"); } })(); const Socket = globalThis.WebSocket;',
    '(async () => { try { fail(); await 0; } finally { new Socket("wss://example.test/invalid"); } })(); const Socket = globalThis.WebSocket;',
    '(async () => { try { await missing; } finally { new Socket("wss://example.test/invalid"); } })(); const Socket = globalThis.WebSocket;',
    'const [Socket] = (items += [globalThis.WebSocket]); new Socket("wss://example.test/invalid");',
    'const values = [globalThis.WebSocket]; const [Socket] = (0, values); new Socket("wss://example.test/invalid");',
    'const [Socket] = (0, [...items, globalThis.WebSocket]); new Socket("wss://example.test/invalid");',
    'let holder; const ws = (holder = require("ws")); ws.WebSocket = Fake; new ws.WebSocket("wss://example.test/invalid");',
    'const ws = (0, require("ws")); ws.WebSocket = Fake; new ws.WebSocket("wss://example.test/invalid");',
    'let holder; const root = (holder = globalThis); root.WebSocket = Fake; new globalThis.WebSocket("wss://example.test/invalid");',
    '(async () => { if (condition) await (async () => { await ready; new Socket("wss://example.test/invalid"); })(); const Socket = globalThis.WebSocket; })();',
    '(async () => { condition && await (async () => { await ready; new Socket("wss://example.test/invalid"); })(); const Socket = globalThis.WebSocket; })();',
    '(async () => { condition ? await (async () => { await ready; new Socket("wss://example.test/invalid"); })() : 0; const Socket = globalThis.WebSocket; })();',
    '(async () => { switch (condition) { case 1: await ready; } new Socket("wss://example.test/invalid"); })(); const Socket = globalThis.WebSocket;',
    '(async () => { maybe?.(await ready); new Socket("wss://example.test/invalid"); })(); const Socket = globalThis.WebSocket;',
    '(async () => { maybe?.[(await ready).count++]; new Socket("wss://example.test/invalid"); })(); const Socket = globalThis.WebSocket;',
    'const ws = require("ws"); if (flag) { ws.WebSocket = Fake; } const Socket = ws.WebSocket; new Socket("wss://example.test/invalid");',
    'const ws = require("ws"); ws.WebSocket.WebSocket = Fake; new ws.WebSocket.WebSocket("wss://example.test/invalid");',
    'const ws = require("ws"); new ws.WebSocket.Other("wss://example.test/invalid");',
  ])(
    "does not turn skipped waits or modified identities into proof: %s",
    (source) => {
      expect(socketEndpoints(source)).toEqual([[], []]);
    },
  );
});

describe("web bundle binding events and structured continuations", () => {
  it.each([
    'const { WebSocket: Socket, unused = new Socket("wss://example.test/event") } = globalThis;',
    'const [Socket, unused = new Socket("wss://example.test/event")] = [globalThis.WebSocket];',
    'const { WebSocket: Socket, [new Socket("wss://example.test/event")]: unused } = globalThis;',
    'const { nested: [Socket], unused = new Socket("wss://example.test/event") } = { nested: [globalThis.WebSocket] };',
  ])(
    "orders binding initialization before later pattern evaluation: %s",
    (source) => {
      const expected = [
        { value: "wss://example.test/event", mechanism: "call:Socket" },
      ];
      expect(socketEndpoints(source)).toEqual([expected, expected]);
    },
  );

  it.each([
    'const { unused = new Socket("wss://example.test/invalid"), WebSocket: Socket } = globalThis;',
    'const [unused = new Socket("wss://example.test/invalid"), Socket] = [undefined, globalThis.WebSocket];',
    'const { [new Socket("wss://example.test/invalid")]: unused, WebSocket: Socket } = globalThis;',
  ])("keeps earlier pattern reads before initialization: %s", (source) => {
    expect(socketEndpoints(source)).toEqual([[], []]);
  });

  it.each([
    'for await (const item of [1]) { new Socket("wss://example.test/structured"); }',
    'for await (const item of []) {} new Socket("wss://example.test/structured");',
    'do { await ready; } while (false); new Socket("wss://example.test/structured");',
    'try { await ready; } finally {} new Socket("wss://example.test/structured");',
    'try {} catch {} finally { await ready; } new Socket("wss://example.test/structured");',
    'for (let i = 0; i < 1; new Socket("wss://example.test/structured"), i++) { await ready; }',
    'const {[await 0]: value} = {}; new Socket("wss://example.test/structured");',
    'const {outer: {[await 0]: value}} = { outer: {} }; new Socket("wss://example.test/structured");',
    'let value; ({[await 0]: value} = {}); new Socket("wss://example.test/structured");',
  ])(
    "carries mandatory structured evaluation into a later read: %s",
    (body) => {
      const expected = [
        { value: "wss://example.test/structured", mechanism: "call:Socket" },
      ];
      expect(
        socketEndpoints(
          `(async () => { ${body} })(); const Socket = globalThis.WebSocket;`,
        ),
      ).toEqual([expected, expected]);
    },
  );

  it.each([
    'for await (const item of [new Socket("wss://example.test/invalid")]) {}',
    'do { break; await ready; } while (false); new Socket("wss://example.test/invalid");',
    'do { if (condition) break; await ready; } while (false); new Socket("wss://example.test/invalid");',
    'for (let i = 0; i < 1; new Socket("wss://example.test/invalid"), i++) { if (condition) continue; await ready; }',
    'try { throw 0; await ready; } finally { new Socket("wss://example.test/invalid"); }',
    'try { if (condition) throw 0; await ready; } catch {} new Socket("wss://example.test/invalid");',
    'const { value = await ready } = { value: 1 }; new Socket("wss://example.test/invalid");',
    'let value; ({[await 0]: value} = { value: new Socket("wss://example.test/invalid") });',
  ])("does not promote skipped/abrupt structured paths: %s", (body) => {
    expect(
      socketEndpoints(
        `(async () => { ${body} })(); const Socket = globalThis.WebSocket;`,
      ),
    ).toEqual([[], []]);
  });

  it.each([
    'const ws = require("ws"); const { WebSocket: Socket } = { WebSocket: ws.WebSocket, later: (ws.WebSocket = class {}) };',
    'const ws = require("ws"); const [Socket] = [ws.WebSocket, (ws.WebSocket = class {})];',
    'const ws = require("ws"); const Saved = ws.WebSocket; ws.WebSocket = class {}; const { copy: Socket } = { copy: Saved };',
  ])(
    "retains a constructor copied before a later export write: %s",
    (capture) => {
      const expected = [
        { value: "wss://example.test/copy", mechanism: "call:Socket" },
      ];
      expect(
        socketEndpoints(`${capture} new Socket("wss://example.test/copy");`),
      ).toEqual([expected, expected]);
    },
  );

  it.each([
    'const ws = require("ws"); const { WebSocket: Socket } = { later: (ws.WebSocket = class {}), WebSocket: ws.WebSocket };',
    'const ws = require("ws"); const { nested: { WebSocket: Socket } } = { nested: ws, later: (ws.WebSocket = class {}) };',
  ])(
    "does not confuse a namespace copy with a constructor copy: %s",
    (capture) => {
      expect(
        socketEndpoints(`${capture} new Socket("wss://example.test/invalid");`),
      ).toEqual([[], []]);
    },
  );
});

describe("web bundle projection kinds, tags and result operands", () => {
  it.each([
    "const [Socket] = { 0: globalThis.WebSocket };",
    "const [[Socket]] = [{ 0: globalThis.WebSocket }];",
    "const { nested: [Socket] } = { nested: { 0: globalThis.WebSocket } };",
  ])("does not substitute object properties for iteration: %s", (capture) => {
    expect(
      socketEndpoints(`${capture} new Socket("wss://example.test/invalid");`),
    ).toEqual([[], []]);
  });

  it.each([
    "const { 0: Socket } = { 0: globalThis.WebSocket };",
    'const { "0": Socket } = [globalThis.WebSocket];',
    "let holder; const Socket = (holder = globalThis.WebSocket);",
    "let holder; const Socket = ((holder = globalThis.WebSocket) as any);",
    'let holder; const Socket = (holder = require("ws").WebSocket);',
    "let holder; const { WebSocket: Socket } = (holder = globalThis);",
  ])("retains exact property and assignment-result captures: %s", (capture) => {
    const expected = [
      { value: "wss://example.test/exact", mechanism: "call:Socket" },
    ];
    expect(
      socketEndpoints(`${capture} new Socket("wss://example.test/exact");`),
    ).toEqual([expected, expected]);
  });

  it.each([
    '(function () { new Socket("wss://example.test/invalid"); })``; const Socket = globalThis.WebSocket;',
    '(() => new Socket("wss://example.test/invalid"))``; const Socket = globalThis.WebSocket;',
    '(function () { new Socket("wss://example.test/invalid"); }).call``; const Socket = globalThis.WebSocket;',
    '(function () { new Socket("wss://example.test/invalid"); }).bind(null)``; const Socket = globalThis.WebSocket;',
    '((function () { new Socket("wss://example.test/invalid"); }) as any)``; const Socket = globalThis.WebSocket;',
    '(function* (strings, x = new Socket("wss://example.test/invalid")) {})``; const Socket = globalThis.WebSocket;',
    '(function* () { new Socket("wss://example.test/invalid"); })``.next(); const Socket = globalThis.WebSocket;',
    'let holder = 0; const Socket = (holder += globalThis.WebSocket); new Socket("wss://example.test/invalid");',
    'let holder = class {}; const Socket = (holder ||= globalThis.WebSocket); new Socket("wss://example.test/invalid");',
  ])("retains eager tag and non-exact assignment boundaries: %s", (source) => {
    expect(socketEndpoints(source)).toEqual([[], []]);
  });

  it.each([
    "`${await ready}`;",
    "`${await ready}${0}`;",
    "(function () {})`${await ready}`;",
    "for (const item of await ready) {}",
    "for (const key in await ready) {}",
  ])(
    "carries mandatory substitutions and iterable evaluation: %s",
    (prefix) => {
      const expected = [
        { value: "wss://example.test/continuation", mechanism: "call:Socket" },
      ];
      expect(
        socketEndpoints(
          `(async () => { ${prefix} new Socket("wss://example.test/continuation"); })(); const Socket = globalThis.WebSocket;`,
        ),
      ).toEqual([expected, expected]);
    },
  );

  it.each([
    'for (const item of await ready) { new Socket("wss://example.test/body"); }',
    'for (const key in await ready) { new Socket("wss://example.test/body"); }',
  ])("carries an awaited iterable into the selected body: %s", (body) => {
    const expected = [
      { value: "wss://example.test/body", mechanism: "call:Socket" },
    ];
    expect(
      socketEndpoints(
        `(async () => { ${body} })(); const Socket = globalThis.WebSocket;`,
      ),
    ).toEqual([expected, expected]);
  });

  it("keeps generator tag bodies deferred until resumption", () => {
    const expected = [
      { value: "wss://example.test/generator", mechanism: "call:Socket" },
    ];
    expect(
      socketEndpoints(
        '(function* () { new Socket("wss://example.test/generator"); })``; const Socket = globalThis.WebSocket;',
      ),
    ).toEqual([expected, expected]);
  });

  it.each([
    "for (const item of []) { await ready; }",
    "for (const key in {}) { await ready; }",
    "`${condition && (await ready)}`;",
  ])("does not promote skipped loop/substitution bodies: %s", (prefix) => {
    expect(
      socketEndpoints(
        `(async () => { ${prefix} new Socket("wss://example.test/invalid"); })(); const Socket = globalThis.WebSocket;`,
      ),
    ).toEqual([[], []]);
  });
});

describe("web bundle mandatory operands and literal projections", () => {
  it.each(["+=", "**=", "<<="])(
    "retains mandatory waits in %s assignments",
    (operator) => {
      expect(
        socketEndpoints(
          `const pending = (async () => { await 0; new Socket("wss://example.test/invalid"); })(); let count = 0; count ${operator} await pending; const Socket = globalThis.WebSocket;`,
        ),
      ).toEqual([[], []]);
    },
  );

  it.each([
    "let count = 0; count += await ready;",
    "let count = 1; count **= await ready;",
    "let count = 0; count <<= await ready;",
    "if (true) await ready;",
    "if (false) {} else await ready;",
    "true ? await ready : 0;",
    "false ? 0 : await ready;",
    "true && (await ready);",
    "false || (await ready);",
    "null ?? (await ready);",
    "(await ready)?.();",
    "(await ready)?.(await other);",
  ])(
    "carries mandatory selected operands into the continuation: %s",
    (prefix) => {
      const expected = [
        { value: "wss://example.test/selected", mechanism: "call:Socket" },
      ];
      expect(
        socketEndpoints(
          `(async () => { ${prefix} new Socket("wss://example.test/selected"); })(); const Socket = globalThis.WebSocket;`,
        ),
      ).toEqual([expected, expected]);
    },
  );

  it.each([
    "if (false) await ready;",
    "unknown ? await ready : 0;",
    "unknown && (await ready);",
    "let value = false; value &&= await ready;",
    "let value = true; value ||= await ready;",
    "let value = 0; value ??= await ready;",
    "null?.(await ready);",
  ])(
    "does not promote unproven branch/assignment/call operands: %s",
    (prefix) => {
      expect(
        socketEndpoints(
          `(async () => { ${prefix} new Socket("wss://example.test/invalid"); })(); const Socket = globalThis.WebSocket;`,
        ),
      ).toEqual([[], []]);
    },
  );

  it.each([
    'import ws = require("ws"); const Socket = ws.WebSocket;',
    'import ws = require("ws"); const { WebSocket: Socket } = ws;',
    'import ws = require("ws"); const alias = ws; const Socket = alias[`WebSocket`];',
    "const [Socket] = [globalThis.WebSocket];",
    "const [, Socket] = [0, globalThis.WebSocket];",
    "const [[Socket]] = [[globalThis.WebSocket]];",
    "const { nested: [Socket] } = { nested: [globalThis.WebSocket] };",
    'const [Socket] = [require("ws").WebSocket];',
  ])(
    "retains exact import-equals members and literal projections: %s",
    (capture) => {
      const expected = [
        { value: "wss://example.test/projected", mechanism: "call:Socket" },
      ];
      expect(
        socketEndpoints(
          `${capture} new Socket("wss://example.test/projected");`,
        ),
      ).toEqual([expected, expected]);
    },
  );

  it.each([
    'import ws = require("other"); const Socket = ws.WebSocket;',
    'import type ws = require("ws"); const Socket = ws.WebSocket;',
    'const Socket = ws.WebSocket; import ws = require("ws");',
    'import ws = require("ws"); ws.WebSocket = class {}; const Socket = ws.WebSocket;',
    'import ws = require("ws"); const alias = ws; alias.WebSocket = class {}; const Socket = ws.WebSocket;',
    'import ws = require("ws"); require("ws").WebSocket = class {}; const Socket = ws.WebSocket;',
    "const [Socket] = [...items, globalThis.WebSocket];",
    "const [Socket = globalThis.WebSocket] = [];",
    "const [Socket] = [class {}];",
    "const box = [globalThis.WebSocket]; box[0] = class {}; const [Socket] = box;",
  ])(
    "leaves overwritten and non-exact constructor projections unresolved: %s",
    (capture) => {
      expect(
        socketEndpoints(`${capture} new Socket("wss://example.test/invalid");`),
      ).toEqual([[], []]);
    },
  );

  it("keeps a constructor captured before an import-equals export write", () => {
    const expected = [
      { value: "wss://example.test/prior", mechanism: "call:Socket" },
    ];
    expect(
      socketEndpoints(
        'import ws = require("ws"); const Socket = ws.WebSocket; ws.WebSocket = class {}; new Socket("wss://example.test/prior");',
      ),
    ).toEqual([expected, expected]);
  });
});

describe("web bundle reached waits and exact expression results", () => {
  it.each([
    "if (false) await pending;",
    "false && (await pending);",
    "true || (await pending);",
    "while (false) await pending;",
    "for (; false;) await pending;",
    "if (unknown) await pending;",
  ])(
    "does not let a skipped or unproven wait constrain initialization: %s",
    (wait) => {
      const expected = [
        { value: "wss://example.test/reached", mechanism: "call:Socket" },
      ];
      expect(
        socketEndpoints(
          `const pending = (async () => { await 0; new Socket("wss://example.test/reached"); })(); ${wait} const Socket = globalThis.WebSocket;`,
        ),
      ).toEqual([expected, expected]);
    },
  );

  it.each([
    "if (true) await pending;",
    "if (false) {} else await pending;",
    "false || (await pending);",
    "null ?? (await pending);",
    "if (false) await pending; await pending;",
  ])("retains a proven wait constraint: %s", (wait) => {
    expect(
      socketEndpoints(
        `const pending = (async () => { await 0; new Socket("wss://example.test/invalid"); })(); ${wait} const Socket = globalThis.WebSocket;`,
      ),
    ).toEqual([[], []]);
  });

  it.each([
    "const value = (await ready).value;",
    "const value = object[await ready];",
    "const value = (await ready)?.value;",
  ])("carries completed member operands into a later read: %s", (prefix) => {
    const expected = [
      { value: "wss://example.test/member", mechanism: "call:Socket" },
    ];
    expect(
      socketEndpoints(
        `(async () => { ${prefix} new Socket("wss://example.test/member"); })(); const Socket = globalThis.WebSocket;`,
      ),
    ).toEqual([expected, expected]);
  });

  it.each([
    "null?.[await ready];",
    "null?.value[await ready];",
    "null?.method(await ready);",
  ])("does not promote a skipped optional operand: %s", (prefix) => {
    expect(
      socketEndpoints(
        `(async () => { ${prefix} new Socket("wss://example.test/invalid"); })(); const Socket = globalThis.WebSocket;`,
      ),
    ).toEqual([[], []]);
  });

  it.each(["globalThis?.WebSocket", "globalThis?.[`WebSocket`]"])(
    "retains a non-null ambient capture: %s",
    (capture) => {
      const expected = [
        { value: "wss://example.test/optional", mechanism: "call:Socket" },
      ];
      expect(
        socketEndpoints(
          `const Socket = ${capture}; new Socket("wss://example.test/optional");`,
        ),
      ).toEqual([expected, expected]);
    },
  );

  it.each([
    'const globalThis = {}; const Socket = globalThis?.WebSocket; new Socket("wss://example.test/invalid");',
    'globalThis.WebSocket = class {}; const Socket = globalThis?.WebSocket; new Socket("wss://example.test/invalid");',
    'let connect; (connect = () => new Socket("wss://example.test/invalid"))(); const Socket = globalThis.WebSocket;',
    'let connect; ((connect = function () { new Socket("wss://example.test/invalid"); }) as any).call(null); const Socket = globalThis.WebSocket;',
    'let Client; new (Client = class { socket = new Socket("wss://example.test/invalid"); })(); const Socket = globalThis.WebSocket;',
  ])(
    "rejects overwritten identities and eager assignment results: %s",
    (source) => {
      expect(socketEndpoints(source)).toEqual([[], []]);
    },
  );

  it("retains a stored assignment result as deferred", () => {
    const expected = [
      {
        value: "wss://example.test/stored-assignment",
        mechanism: "call:Socket",
      },
    ];
    expect(
      socketEndpoints(
        'let connect; connect = () => new Socket("wss://example.test/stored-assignment"); const Socket = globalThis.WebSocket; connect();',
      ),
    ).toEqual([expected, expected]);
  });
});

describe("web bundle constructor captures before repeating writes", () => {
  it.each([
    "for (const item of items) { ws.WebSocket = class {}; }",
    "for (const item in items) { ws.WebSocket = class {}; }",
    "while (condition) { ws.WebSocket = class {}; }",
    "do { ws.WebSocket = class {}; } while (condition);",
    "for (const item of items) { for (const child of item) { ws.WebSocket = class {}; } }",
  ])(
    "retains a constructor already captured before the whole loop: %s",
    (loop) => {
      const expected = [
        { value: "wss://example.test/captured-loop", mechanism: "call:Socket" },
      ];
      expect(
        socketEndpoints(
          `const ws = require("ws"); const Socket = ws.WebSocket; ${loop} new Socket("wss://example.test/captured-loop");`,
        ),
      ).toEqual([expected, expected]);
    },
  );

  it.each([
    'const ws = require("ws"); for (const item of items) { const Socket = ws.WebSocket; ws.WebSocket = class {}; new Socket("wss://example.test/local"); }',
    'const ws = require("ws"); for (const item of items) { ws.WebSocket = class {}; } const Socket = ws.WebSocket; new Socket("wss://example.test/local");',
    'const ws = require("ws"); const alias = ws; for (const item of items) { ws.WebSocket = class {}; } new alias.WebSocket("wss://example.test/local");',
  ])(
    "keeps repeated captures and later namespace selections unresolved: %s",
    (source) => {
      expect(socketEndpoints(source)).toEqual([[], []]);
    },
  );
});

describe("web bundle API classification parity", () => {
  it("reads storage open versions as storage rather than endpoints in both analyzers", () => {
    const source = `
      indexedDB.open(databaseName, "2");
      window.indexedDB.open(databaseName, "/v3");
      indexedDB.open("APP", "4");
      indexedDB.open("GET", "/storage-named-xhr");
    `;
    expect(
      analyzeCapturedWebBundle(inspection(source)).observations.endpoints.map(
        ({ value }) => value,
      ),
    ).toEqual(["/storage-named-xhr"]);
    const analysis = analyzeJavaScriptStaticSource(source);
    expect(analysis.endpoints.map(({ value }) => value)).toEqual([
      "/storage-named-xhr",
    ]);
    expect(analysis.storage.map(({ kind }) => kind)).toEqual([
      "indexed-db",
      "indexed-db",
      "indexed-db",
      "indexed-db",
    ]);
  });

  it("uses lexical receiver facts for overloaded open calls", () => {
    const result = analyzeCapturedWebBundle(
      inspection(`
        const popup = window;
        popup.open(url, "/preview");
        {
          const indexedDB = { open() {} };
          indexedDB.open("PROPFIND", "/dav");
          indexedDB.open(databaseName, "2");
        }
        const xhr = new XMLHttpRequest();
        xhr.open(method, "/api");
      `),
    );
    expect(
      result.observations.endpoints.map(({ value }) => value).sort(),
    ).toEqual(["/api", "/dav"]);
  });

  it("classifies optional and one-hop aliased open calls", () => {
    const source = `
      const popup = window;
      popup?.open(url, "/preview");
      const idb = indexedDB;
      idb.open(databaseName, "2");
      const xhr = new XMLHttpRequest();
      xhr?.open(method, "/api");
    `;
    const bundle = analyzeCapturedWebBundle(inspection(source));
    expect(bundle.observations.endpoints.map(({ value }) => value)).toEqual([
      "/api",
    ]);
    const staticAnalysis = analyzeJavaScriptStaticSource(source);
    expect(staticAnalysis.endpoints.map(({ value }) => value)).toEqual([
      "/api",
    ]);
    expect(staticAnalysis.storage.map(({ kind }) => kind)).toEqual([
      "indexed-db",
    ]);
  });

  it("keeps HTTP-method-named reads of provable keyed collections out of endpoints", () => {
    const result = analyzeCapturedWebBundle(
      inspection(`
        axios.get("https://api.example.test/users");
        api.get("users");
        client.delete("cache-key");
        new Map().get("map-key");
        new URLSearchParams(location.search).get("q");
        new Headers(init).delete("x-trace");
        new FormData(form).get("file");
        response.headers.get("content-type");
        request?.headers.delete("cookie");
        new URL(location.href).searchParams.get("page");
        api.headers.post("/v1/headers");
        api.searchParams.request("/search");
        new Headers().get("/users");
        api.headers.get("https://api.example.test/headers");
        api.searchParams.delete("../search");
      `),
    );
    expect(
      result.observations.endpoints.map(({ value }) => value).sort(),
    ).toEqual([
      "../search",
      "/search",
      "/users",
      "/v1/headers",
      "https://api.example.test/headers",
      "https://api.example.test/users",
    ]);
    expect(
      result.inferences
        .filter(({ kind }) => kind === "endpoint_candidate")
        .map(({ value }) => value)
        .sort(),
    ).toEqual(["cache-key", "users"]);
  });

  it("keeps undici header-store reads out of endpoint observations", () => {
    const result = analyzeCapturedWebBundle(
      inspection(`
        response.headersList.get("location", true);
        request.headersList.delete("authorization");
        request.headersList.get("/header-list");
        api.get("/api/users");
      `),
    );
    expect(result.observations.endpoints.map(({ value }) => value)).toEqual([
      "/header-list",
      "/api/users",
    ]);
    expect(
      result.inferences
        .filter(({ kind }) => kind === "endpoint_candidate")
        .map(({ value }) => value),
    ).toEqual([]);
  });
});

describe("web bundle explicit request reference forms", () => {
  it("recognizes URL, path, query and fragment forms after excluding lookup receivers", () => {
    const references = [
      "http://api.example.test/users",
      "https://api.example.test/users?q=1#part",
      "ws://api.example.test/events",
      "wss://api.example.test/events",
      "http:api.example.test/users",
      "https:api.example.test/users?q=1&tag=a&tag=b#part",
      "https:api.example.test:443/a/../b?x=a+b&x=two#part",
      "ws:api.example.test/events",
      "wss:api.example.test/events",
      "HtTpS:/api.example.test/users",
      String.raw`https:\api.example.test\users`,
      "https://[invalid",
      "//api.example.test/users",
      "/api/users",
      "./users",
      "../users",
      "?",
      "?page=2&tag=a&tag=b#section",
      "#",
      "#section",
      "#frag?tag=a&tag=b",
    ];
    const ambiguous = [
      "",
      ".",
      "..",
      "users",
      "%23section",
      "%3Fpage=2",
      " #section",
      " https:api.example.test/users",
      "https:",
      "http:?page=2",
      "ws:#section",
      "https:[invalid",
      "https:api.example.test:99999",
      "ftp:api.example.test/users",
      "file:/users",
      "data:text/plain,users",
    ];
    const source = `
      ${references.map((value) => `api.get(${JSON.stringify(value)});`).join("\n")}
      ${ambiguous.map((value) => `api.get(${JSON.stringify(value)});`).join("\n")}
      xhr.open(method, "?view=1");
      xhr.open(method, "#view=1");
      xhr.open("GET", "#literal=1");
      xhr.open(method, "https:api.example.test/xhr");
      request("POST", target);
      snackBar.open(message, "X");
      new Map().get("?map-key");
      new Map().get("#map-key");
      new Map().get("https:api.example.test/map-key");
      new Headers().delete("?header-key");
      new Headers().delete("#header-key");
      new URLSearchParams().get("?parameter-key");
      new URLSearchParams().get("#parameter-key");
      response.headers.get("?response-key");
      response.headers.get("#response-key");
      const config = vscode.workspace.getConfiguration("git");
      config.get("?setting");
      config.get("#setting");
      config.get("https:api.example.test/setting");
      window.open(url, "?window-target");
      window.open(url, "#window-target");
      indexedDB.open(name, "?database-version");
      indexedDB.open(name, "#database-version");
      caches.open(name, "#cache-name");
      fs.open(path, "r");
    `;
    const expected = [
      ...references,
      "?view=1",
      "#view=1",
      "#literal=1",
      "https:api.example.test/xhr",
    ].sort();
    const expectedCandidates = [...ambiguous, "POST", "X"].sort();
    const web = analyzeCapturedWebBundle(inspection(source));
    expect(web.observations.endpoints.map(({ value }) => value).sort()).toEqual(
      expected,
    );
    expect(
      web.inferences
        .filter(({ kind }) => kind === "endpoint_candidate")
        .map(({ value }) => value)
        .sort(),
    ).toEqual(expectedCandidates);
    const analyzed = analyzeJavaScriptStaticSource(source);
    expect(
      analyzed.endpoints
        .filter(({ interpretation }) => interpretation === undefined)
        .map(({ value }) => value)
        .sort(),
    ).toEqual(expected);
    expect(
      analyzed.endpoints
        .filter(({ interpretation }) => interpretation === "candidate")
        .map(({ value }) => value)
        .sort(),
    ).toEqual(expectedCandidates);
  });
});

describe("web bundle endpoint candidate classification", () => {
  it("keeps ambiguous HTTP-method arguments as candidates instead of endpoint observations", () => {
    const source = `
      fetch("login");
      api.get("/api/users");
      api.get("users");
      form.get("passwordControl");
      translate.get("ADDRESS_ADDED");
      cookieService.put("token", value);
      http.request("POST", target);
      snackBar.open(message, "X");
      xhr.open(method, "login");
      xhr.open("GET", "ping");
    `;
    const result = analyzeCapturedWebBundle(inspection(source));
    expect(
      result.observations.endpoints.map(({ value }) => value).sort(),
    ).toEqual(["/api/users", "login", "ping"]);
    const candidates = result.inferences.filter(
      ({ kind }) => kind === "endpoint_candidate",
    );
    expect(candidates.map(({ value }) => value).sort()).toEqual([
      "ADDRESS_ADDED",
      "POST",
      "X",
      "login",
      "passwordControl",
      "token",
      "users",
    ]);
    expect(
      candidates.every(
        ({ confidence, basis }) =>
          confidence === "low" &&
          basis.length === 1 &&
          basis[0]?.artifact_sha256 ===
            createWebTextArtifact(source, "text/javascript").sha256 &&
          basis[0]?.line !== null &&
          basis[0]?.detector.startsWith("call:"),
      ),
    ).toBe(true);
    const staticEndpoints = analyzeJavaScriptStaticSource(source).endpoints;
    expect(
      staticEndpoints
        .filter(({ interpretation }) => interpretation === "candidate")
        .map(({ value }) => value)
        .sort(),
    ).toEqual(candidates.map(({ value }) => value).sort());
    expect(
      staticEndpoints
        .filter(({ interpretation }) => interpretation === undefined)
        .map(({ value }) => value)
        .sort(),
    ).toEqual(result.observations.endpoints.map(({ value }) => value).sort());
    expect(webBundleAnalysisSchema.parse(result)).toEqual(result);
  });

  it("deduplicates repeated candidate sites while keeping script, value and detector identity", () => {
    const source = `${'form.get("name");\n'.repeat(5_000)}translate.get("name");\nform.get("other");`;
    const captured = inspection(source);
    const first = captured.scripts.items[0];
    if (first === undefined) throw new Error("Missing captured script fixture");
    const secondKey = `scr_${"2".repeat(64)}`;
    const result = analyzeCapturedWebBundle({
      ...captured,
      scripts: {
        total: 2,
        items: [
          first,
          {
            ...first,
            script_key: secondKey,
            url: `${origin}/assets/second.js`,
          },
        ],
      },
    });
    const candidates = result.inferences.filter(
      ({ kind }) => kind === "endpoint_candidate",
    );
    expect(candidates).toHaveLength(6);
    for (const scriptKey of [first.script_key, secondKey]) {
      const local = candidates.filter(
        ({ basis }) => basis[0]?.script_key === scriptKey,
      );
      expect(
        local.map(({ value, basis }) => [value, basis[0]?.detector]),
      ).toEqual([
        ["name", "call:form.get:unverified-network-receiver"],
        ["name", "call:translate.get:unverified-network-receiver"],
        ["other", "call:form.get:unverified-network-receiver"],
      ]);
      expect(local[0]?.basis[0]).toMatchObject({
        line: 1,
        column: 0,
        artifact_sha256: createWebTextArtifact(source, "text/javascript")
          .sha256,
      });
    }
    expect(result.observations.endpoints).toEqual([]);
    expect(result.capture.source_artifacts).toHaveLength(2);
    expect(result.completeness).toMatchObject({
      status: "complete",
      parsed_scripts: 2,
    });
    expect(result.limitations).toContain(
      'Endpoint candidates are deduplicated by script, value and detector; basis retains only the first matching source coordinate. They are not a complete call-site inventory or a runtime occurrence count. completeness.status="complete" describes examination of captured source, not a call-site census.',
    );
  });
});

describe("web bundle configuration and navigation parity", () => {
  it("keeps configuration setting reads out of endpoints in both analyzers", () => {
    const source = `
      import vscodeDefault from "vscode";
      vscodeDefault.workspace.getConfiguration("git").get("default-setting");
      vscode.workspace.getConfiguration("git").get("autofetch");
      workspace.getConfiguration("git").get("enabled", true);
      const config = vscode.workspace.getConfiguration("git");
      config.get("autofetchPeriod", 180);
      config.get("/v1/settings");
      let c = Mt.workspace.getConfiguration("git", uri), l = c.get("timeline.date");
      let changed = vscode.workspace.getConfiguration("git");
      changed = api;
      changed.get("reassigned");
      const maybe = flag ? vscode.workspace.getConfiguration("git") : api;
      maybe.get("conditional");
      {
        const config = api;
        config.get("shadowed");
      }
      api.get("users");
      const client = getConfiguration("/api/v1");
      client.get("accounts");
      http.getConfiguration(baseUrl).get("orders");
      {
        const workspace = { getConfiguration: () => api };
        workspace.getConfiguration("/api").get("local-users");
      }
      {
        const vscode = { workspace: { getConfiguration: () => api } };
        vscode.workspace.getConfiguration("/api").get("local-orders");
      }
    `;
    const expected = [
      "/v1/settings",
      "accounts",
      "conditional",
      "local-orders",
      "local-users",
      "orders",
      "reassigned",
      "shadowed",
      "users",
    ];
    const web = analyzeCapturedWebBundle(inspection(source));
    expect(web.observations.endpoints.map(({ value }) => value)).toEqual([
      "/v1/settings",
    ]);
    expect(
      web.inferences
        .filter(({ kind }) => kind === "endpoint_candidate")
        .map(({ value }) => value)
        .sort(),
    ).toEqual(expected.slice(1));
    expect(
      analyzeJavaScriptStaticSource(source)
        .endpoints.map(({ value }) => value)
        .sort(),
    ).toEqual(expected);
  });

  it("classifies proven VS Code extension state reads as non-endpoints", () => {
    const reads = `
      context.globalState.get("lastVersion");
      this.workspaceState.get("closedRepositories", []);
      context?.globalState.get("onboarded");
      context.globalState.get("/v1/state");
      context.secrets.get("token");
      api.get("users");
    `;
    const analyze = (source: string) => {
      const web = analyzeCapturedWebBundle(inspection(source));
      const staticAnalysis = analyzeJavaScriptStaticSource(source);
      return {
        web: {
          endpoints: web.observations.endpoints
            .map(({ value }) => value)
            .sort(),
          candidates: web.inferences
            .filter(({ kind }) => kind === "endpoint_candidate")
            .map(({ value }) => value)
            .sort(),
        },
        application: {
          endpoints: staticAnalysis.endpoints
            .filter(({ interpretation }) => interpretation === undefined)
            .map(({ value }) => value)
            .sort(),
          candidates: staticAnalysis.endpoints
            .filter(({ interpretation }) => interpretation === "candidate")
            .map(({ value }) => value)
            .sort(),
        },
      };
    };
    const proven = {
      endpoints: ["/v1/state"],
      candidates: ["token", "users"],
    };
    expect(analyze(`const vscode = require("vscode");${reads}`)).toEqual({
      web: proven,
      application: proven,
    });
    expect(analyze(`import * as vscode from "vscode";${reads}`)).toEqual({
      web: proven,
      application: proven,
    });
    const unproven = {
      endpoints: ["/v1/state"],
      candidates: [
        "closedRepositories",
        "lastVersion",
        "onboarded",
        "token",
        "users",
      ],
    };
    expect(analyze(`const vscode = require("./vscode");${reads}`)).toEqual({
      web: unproven,
      application: unproven,
    });
  });

  it("recognizes loadURL endpoints like static analysis", () => {
    const result = analyzeCapturedWebBundle(
      inspection('window.win.loadURL("https://embedded.test/app");'),
    );
    expect(result.observations.endpoints).toContainEqual(
      expect.objectContaining({ value: "https://embedded.test/app" }),
    );
  });
});

describe("web bundle artifact metadata", () => {
  it("preserves long provider media types in artifact summaries", () => {
    const result = analyzeCapturedWebBundle(inspection("export {};"));
    const mediaType = `application/${"x".repeat(300)}`;
    const artifact = result.capture.source_artifacts[0] ?? {
      sha256: "0".repeat(64),
      bytes: 0,
      media_type: "application/javascript",
      charset: "utf-8" as const,
      text_available: true as const,
    };

    expect(
      webBundleAnalysisSchema.parse({
        ...result,
        capture: {
          ...result.capture,
          source_artifacts: [{ ...artifact, media_type: mediaType }],
        },
      }).capture.source_artifacts[0]?.media_type,
    ).toBe(mediaType);
  });
});

describe("deep captured web bundle syntax", () => {
  it("retains evidence after a parser-admitted deep property chain", () => {
    const source = `const value = root${".next".repeat(12_000)};\nimport "./last.js";\nfetch("/after");`;
    const result = analyzeCapturedWebBundle(inspection(source));
    expect(result.completeness).toMatchObject({
      status: "complete",
      parsed_scripts: 1,
      parse_failures: 0,
    });
    expect(result.observations.chunks.edges).toContainEqual(
      expect.objectContaining({
        kind: "static_import",
        specifier: "./last.js",
        resolved_url: `${origin}/assets/last.js`,
        location: expect.objectContaining({ line: 2, column: 0 }),
      }),
    );
    expect(result.observations.endpoints).toContainEqual(
      expect.objectContaining({
        value: "/after",
        location: expect.objectContaining({ line: 3, column: 0 }),
      }),
    );
  });
});

const inspection = (source: string) =>
  webPageInspectionSchema.parse({
    browser: {
      product: "Fake Chrome",
      protocol_version: "1.3",
      revision: "1",
      user_agent: "fake",
      js_version: "1",
    },
    target: {
      target_id: "page-1",
      type: "page",
      title: "App",
      url: `${origin}/app`,
      origin,
      attached: false,
    },
    capture_window: {
      started_at: "2026-07-14T00:00:00.000Z",
      ended_at: "2026-07-14T00:00:01.000Z",
      observation_ms: 1_000,
    },
    completeness: {
      status: "attach_limited",
      conditions: ["attach_limited"],
      policy_filtered_sections: [],
      attach_limited_sections: ["network_requests"],
      truncated_sections: [],
      unavailable_sections: [],
      excluded: [],
      dropped_events: {
        scripts: 0,
        network_requests: 0,
        console_events: 0,
        websocket_connections: 0,
        websocket_frames: 0,
        webmcp_tools: 0,
        timeline_events: 0,
        total: 0,
      },
    },
    frames: [],
    dom: { total_nodes: 0, nodes: [] },
    accessibility: {
      total_nodes: 0,
      text_capture: {
        status: "not_approved",
        retained_bytes: 0,
        excluded_fields: 0,
      },
      nodes: [],
    },
    scripts: {
      total: 1,
      items: [
        {
          script_key: `scr_${"1".repeat(64)}`,
          url: `${origin}/assets/app.js`,
          origin,
          cdp_hash: "hash",
          length: Buffer.byteLength(source),
          is_module: true,
          language: "JavaScript",
          source_map_url: null,
          resource_reconciliation: {
            status: "unmatched",
            reason: "no_exact_sanitized_url",
          },
          source: {
            included: true,
            artifact: createWebTextArtifact(source, "text/javascript"),
          },
        },
      ],
    },
    resources: [],
    network: {
      requests: [],
      websocket_connections: [],
      coverage_started_at: "2026-07-14T00:00:00.000Z",
      prior_activity_available: false,
    },
    console: {
      events: [],
      coverage_started_at: "2026-07-14T00:00:00.000Z",
      prior_activity_available: false,
    },
    workers: [],
    metadata: {
      responses: [],
      dom_urls: [],
      agent_hints: [],
      excluded_dom_urls: 0,
      headers_allowlisted: true,
    },
    storage: {
      origin,
      usage_bytes: null,
      quota_bytes: null,
      local_storage_keys: [],
      session_storage_keys: [],
      indexed_db_names: [],
      cache_names: [],
      values_redacted: true,
    },
    limitations: [],
  });

it("recognizes expression-free template literals as route properties", () => {
  const result = analyzeCapturedWebBundle(
    inspection(`
      const routes = [
        { path: \`score-board\`, component: ScoreBoard },
        { route: \`administration\`, component: Admin },
        { path: \`/user/\${name}\`, component: Dynamic },
      ];
    `),
  );

  expect(result.observations.routes.map(({ value }) => value)).toEqual([
    "score-board",
    "administration",
  ]);
});

it("uses the shared parser for decorated captured scripts", () => {
  const result = analyzeCapturedWebBundle(
    inspection(`@sealed class Widget {} fetch('/decorated');`),
  );

  expect(result.completeness).toMatchObject({
    status: "complete",
    parsed_scripts: 1,
    parse_failures: 0,
  });
  expect(result.observations.endpoints).toEqual([
    expect.objectContaining({ value: "/decorated" }),
  ]);
});

it("keeps bare module locations unresolved without inventing URL-relative paths", () => {
  const result = analyzeCapturedWebBundle(
    inspection(`
    import "package-name";
    import("@scope/package");
    require("package-name");
    import "./actual.js";
    importScripts("worker.js");
  `),
  );
  for (const specifier of ["package-name", "@scope/package"])
    expect(
      result.observations.chunks.edges
        .filter((edge) => edge.specifier === specifier)
        .every((edge) => edge.resolved_url === null),
    ).toBe(true);
  expect(
    result.observations.chunks.edges.find(
      (edge) => edge.specifier === "./actual.js",
    )?.resolved_url,
  ).toBe(`${origin}/assets/actual.js`);
  expect(
    result.observations.chunks.edges.find(
      (edge) => edge.specifier === "worker.js",
    )?.resolved_url,
  ).toBe(`${origin}/assets/worker.js`);
});

it("retains each literal importScripts argument in source order", () => {
  const result = analyzeCapturedWebBundle(
    inspection(
      'importScripts("first.js", dynamicValue, "second.js", "first.js");',
    ),
  );
  expect(
    result.observations.chunks.edges
      .filter(({ kind }) => kind === "worker_import")
      .map(({ specifier }) => specifier),
  ).toEqual(["first.js", "second.js"]);
});

describe("web metadata key semantics", () => {
  it("keeps computed metadata keys and overwrite order conservative", () => {
    const result = analyzeCapturedWebBundle(
      inspection(`
      const path = "description";
      const routes = [{ [path]: "/not-a-route" }, { ["path"]: "/real" }];
      document.modelContext.registerTool({
        name: "old", name: "new",
        inputSchema: { properties: { [name]: {}, literal: {} } }
      });
      document.modelContext.registerTool({ name: "old", ...dynamic });
      document.modelContext.registerTool({ name: "old", [name]: "dynamic" });
      document.modelContext.registerTool({ name: "old", get name() {} });
      document.modelContext.registerTool({ ...dynamic, ["name"]: "restored" });
      document.modelContext.registerTool({ name: "valid", [""]: 0 });
    `),
    );

    expect(result.observations.routes.map(({ value }) => value)).toEqual([
      "/real",
    ]);
    expect(result.observations.webmcp_declarations).toEqual([
      expect.objectContaining({
        name: "new",
        schema_property_names: ["literal"],
      }),
      expect.objectContaining({ name: null }),
      expect.objectContaining({ name: "restored" }),
      expect.objectContaining({ name: "valid" }),
    ]);
  });

  it("projects only exact input schema property names", () => {
    const result = analyzeCapturedWebBundle(
      inspection(`
      document.modelContext.registerTool({
        name: "literal",
        inputSchema: {
          type: "object",
          properties: { type: {}, properties: {}, "": {}, [dynamicKey]: {}, ...dynamicProperties }
        }
      });
      document.modelContext.registerTool({ name: "missing properties", inputSchema: { type: "object" } });
      document.modelContext.registerTool({ name: "dynamic properties", inputSchema: { properties: dynamicProperties } });
      document.modelContext.registerTool({ name: "null properties", inputSchema: { properties: null } });
      document.modelContext.registerTool({ name: "missing schema" });
      document.modelContext.registerTool({ name: "dynamic schema", inputSchema: schema });
      document.modelContext.registerTool({ name: "null schema", inputSchema: null });
      document.modelContext.registerTool({ name: "spread schema", inputSchema: { ...schema } });
      document.modelContext.registerTool({
        name: "computed literal keys",
        ["inputSchema"]: { ["properties"]: { [""]: {}, ["literal"]: {}, [dynamicKey]: {} } }
      });
    `),
    );

    expect(
      result.observations.webmcp_declarations.map(
        ({ name, schema_property_names }) => ({ name, schema_property_names }),
      ),
    ).toEqual([
      { name: "literal", schema_property_names: ["", "properties", "type"] },
      { name: "missing properties", schema_property_names: [] },
      { name: "dynamic properties", schema_property_names: [] },
      { name: "null properties", schema_property_names: [] },
      { name: "missing schema", schema_property_names: [] },
      { name: "dynamic schema", schema_property_names: [] },
      { name: "null schema", schema_property_names: [] },
      { name: "spread schema", schema_property_names: [] },
      { name: "computed literal keys", schema_property_names: ["", "literal"] },
    ]);
  });
});

it("retains WebMCP declarations through optional member and call chaining", () => {
  const result = analyzeCapturedWebBundle(
    inspection(`
      document.modelContext?.registerTool({ name: "optional member" });
      document.modelContext.registerTool?.({ name: "optional call" });
    `),
  );

  expect(result.observations.webmcp_declarations).toEqual([
    expect.objectContaining({
      name: "optional member",
      trust: "page-declared-untrusted",
    }),
    expect.objectContaining({
      name: "optional call",
      trust: "page-declared-untrusted",
    }),
  ]);
});

it("reads expression-free template dynamic imports as chunk edges", () => {
  const result = analyzeCapturedWebBundle(
    inspection(`
        import(\`./lazy.js\`);
        import("./quoted.js");
        import(\`./\${name}.js\`);
      `),
  );

  expect(result.observations.chunks.edges).toEqual([
    expect.objectContaining({
      kind: "dynamic_import",
      specifier: "./lazy.js",
      resolved_url: `${origin}/assets/lazy.js`,
    }),
    expect.objectContaining({
      kind: "dynamic_import",
      specifier: "./quoted.js",
    }),
  ]);
});

it("does not infer call names from dynamic computed identifiers", () => {
  const result = analyzeCapturedWebBundle(
    inspection(`
        const fetch = "render";
        const require = "render";
        const registerTool = "render";
        window[fetch]("/render-only");
        window[require]("./not-a-module.js");
        document.modelContext[registerTool]({ name: "not-a-tool" });
      `),
  );

  expect(result.observations.endpoints).toEqual([]);
  expect(result.observations.chunks.edges).toEqual([]);
  expect(result.observations.webmcp_declarations).toEqual([]);
});

it("retains direct and literal computed call names", () => {
  const result = analyzeCapturedWebBundle(
    inspection(`
        window.fetch("/direct");
        window["fetch"]("/literal");
    window[receiver].fetch("/nested-receiver");
        window.require("./direct.js");
        window["require"]("./literal.js");
        document.modelContext["registerTool"]({ name: "literal-tool" });
      `),
  );

  expect(result.observations.endpoints.map(({ value }) => value)).toEqual([
    "/direct",
    "/literal",
    "/nested-receiver",
  ]);
  expect(
    result.observations.chunks.edges.map(({ specifier }) => specifier),
  ).toEqual(["./direct.js", "./literal.js"]);
  expect(result.observations.webmcp_declarations).toEqual([
    expect.objectContaining({ name: "literal-tool" }),
  ]);
});

it("requires WebMCP receiver and method names to occupy exact member segments", () => {
  const result = analyzeCapturedWebBundle(
    inspection(`
      navigator.modelContext.registerTool({ name: "navigator" });
      local.modelContext.registerTool({ name: "exact nested" });
      const appmodelContext = { registerTool() {} };
      appmodelContext.registerTool({ name: "receiver suffix" });
      const app = { analyticsmodelContext: { registerTool() {} } };
      app.analyticsmodelContext.registerTool({ name: "nested suffix" });
      window["modelContext.registerTool"]({ name: "dotted property" });
      window["modelContext"].registerTool({ name: "computed receiver" });
    `),
  );

  expect(result.observations.webmcp_declarations).toEqual([
    expect.objectContaining({ name: "navigator" }),
    expect.objectContaining({ name: "exact nested" }),
    expect.objectContaining({ name: "computed receiver" }),
  ]);
});

it("recognizes tRPC procedures and named GraphQL operations in captured scripts", () => {
  const result = analyzeCapturedWebBundle(
    inspection(`
      const n = createTRPCClient({ links: [httpBatchLink({ url: "/api/trpc" })] });
      e.invoice.list.useQuery({ competencia: "2026-09" });
      n.empresa.byCnpj.query("00000000000191");
      const q = "query ListarNotas($competencia: String!) { notas { id } }";
      this.client.query({ query: q });
    `),
  );
  expect(
    result.observations.endpoints.map(({ value, mechanism }) => ({
      value,
      mechanism,
    })),
  ).toEqual([
    { value: "/api/trpc", mechanism: "trpc:link:httpBatchLink" },
    { value: "invoice.list", mechanism: "trpc:procedure:useQuery" },
    { value: "empresa.byCnpj", mechanism: "trpc:procedure:query" },
    { value: "ListarNotas", mechanism: "graphql:query" },
  ]);
});

it("keeps RPC lexical identity and bundled factory recognition in captured scripts", () => {
  const longOperation = "Operation" + "x".repeat(512);
  const document =
    "#" +
    "comment".repeat(700) +
    "\nquery " +
    longOperation +
    " { users { id } }";
  const result = analyzeCapturedWebBundle(
    inspection(`
    function first() { const c = createTRPCClient({}); }
    function unrelated(c) { c.users.query("select 1"); }
    const c = (0, t.createTRPCClient)({ links: [(0, t.httpBatchLink)({ url: "/api/rpc" })] });
    c.posts.query();
    const doc = ${JSON.stringify(document)};
  `),
  );
  expect(
    result.observations.endpoints.map(({ value, mechanism }) => ({
      value,
      mechanism,
    })),
  ).toEqual([
    { value: "/api/rpc", mechanism: "trpc:link:httpBatchLink" },
    { value: "posts", mechanism: "trpc:procedure:query" },
    { value: longOperation, mechanism: "graphql:query" },
  ]);
  expect(result.completeness.status).toBe("complete");
});

it("retains distinct WebMCP descriptions and names while deduplicating equivalent properties", () => {
  const result = analyzeCapturedWebBundle(
    inspection(`
      document.modelContext.registerTool({ name: "lookup", description: "first", inputSchema: { properties: { alpha: {} } } });
      document.modelContext.registerTool({ name: "lookup", description: "second", inputSchema: { properties: { alpha: {} } } });
      document.modelContext.registerTool({ name: "equivalent", inputSchema: { properties: { alpha: {}, beta: {} } } });
      document.modelContext.registerTool({ name: "equivalent", inputSchema: { properties: { beta: {}, alpha: {}, alpha: {} } } });
      document.modelContext.registerTool({ description: "unnamed" });
      document.modelContext.registerTool({ name: "", description: "unnamed" });
    `),
  );

  expect(
    result.observations.webmcp_declarations.map(
      ({ name, description, schema_property_names }) => ({
        name,
        description,
        schema_property_names,
      }),
    ),
  ).toEqual([
    {
      name: "lookup",
      description: "first",
      schema_property_names: ["alpha"],
    },
    {
      name: "lookup",
      description: "second",
      schema_property_names: ["alpha"],
    },
    {
      name: "equivalent",
      description: null,
      schema_property_names: ["alpha", "beta"],
    },
    { name: null, description: "unnamed", schema_property_names: [] },
    { name: "", description: "unnamed", schema_property_names: [] },
  ]);
  expect(result.observations.webmcp_declarations[2]?.location).toEqual({
    script_key: `scr_${"1".repeat(64)}`,
    line: 4,
    column: 6,
  });
  expect(
    result.observations.webmcp_declarations.every(
      ({ trust }) => trust === "page-declared-untrusted",
    ),
  ).toBe(true);
});

const exactReturnedPromiseAndClassPhaseCases = [
  {
    name: "fresh static class method",
    source:
      "(class { static run() { new Socket('wss://example.test/review-phase') } }).run(); const Socket = globalThis.WebSocket;",
    present: false,
  },
  {
    name: "literal wrapper returned promise",
    source:
      "(async () => { const pending = (async () => { await 0; new Socket('wss://example.test/review-phase') })(); await (() => pending)(); const Socket = globalThis.WebSocket; })();",
    present: false,
  },
  {
    name: "labeled suspension",
    source:
      "(async () => { label: { await 0; } new Socket('wss://example.test/review-phase') })(); const Socket = globalThis.WebSocket;",
    present: true,
  },
  {
    name: "awaited abrupt finally entry",
    source:
      "(async () => { try { throw await 0; } finally { new Socket('wss://example.test/review-phase') } })(); const Socket = globalThis.WebSocket;",
    present: true,
  },
  {
    name: "destructured promise identity",
    source:
      "export {}; const { pending } = { pending: import('ws') }; const { WebSocket: Socket } = await pending; new Socket('wss://example.test/review-phase');",
    present: true,
  },
  {
    name: "instance auto accessor",
    source:
      "const Client = class { accessor socket = new Socket('wss://example.test/review-phase') }; const Socket = globalThis.WebSocket; new Client();",
    present: true,
  },
  {
    name: "JSX child suspension",
    source:
      "(async () => { <div>{await ready}</div>; new Socket('wss://example.test/review-phase'); })(); const Socket = globalThis.WebSocket;",
    present: true,
  },
  {
    name: "computed static method",
    source:
      "(class { static [`run`]() { new Socket('wss://example.test/review-phase') } })[`run`](); const Socket = globalThis.WebSocket;",
    present: false,
  },
  {
    name: "static method call wrapper",
    source:
      "(class { static run() { new Socket('wss://example.test/review-phase') } }).run.call(null); const Socket = globalThis.WebSocket;",
    present: false,
  },
  {
    name: "async static continuation",
    source:
      "(class { static async run() { await 0; new Socket('wss://example.test/review-phase') } }).run(); const Socket = globalThis.WebSocket;",
    present: true,
  },
  {
    name: "unresumed generator method",
    source:
      "(class { static *run() { new Socket('wss://example.test/review-phase') } }).run(); const Socket = globalThis.WebSocket;",
    present: true,
  },
  {
    name: "stored class method",
    source:
      "const run = (class { static run() { new Socket('wss://example.test/review-phase') } }).run; const Socket = globalThis.WebSocket; run();",
    present: true,
  },
  {
    name: "field initialization after methods",
    source:
      "(class { static run = () => new Socket('wss://example.test/review-phase'); static run() {} }).run(); const Socket = globalThis.WebSocket;",
    present: false,
  },
  {
    name: "overridden method remains deferred",
    source:
      "(class { static run = () => {}; static run() { new Socket('wss://example.test/review-phase') } }).run(); const Socket = globalThis.WebSocket;",
    present: true,
  },
  {
    name: "label breaks before suspension",
    source:
      "(async () => { label: { break label; await 0; } new Socket('wss://example.test/review-phase'); })(); const Socket = globalThis.WebSocket;",
    present: false,
  },
  {
    name: "label suspends before break",
    source:
      "(async () => { label: { await 0; break label; } new Socket('wss://example.test/review-phase'); })(); const Socket = globalThis.WebSocket;",
    present: true,
  },
  {
    name: "labeled stored function does not suspend",
    source:
      "(async () => { label: { const run = async () => await 0; } new Socket('wss://example.test/review-phase'); })(); const Socket = globalThis.WebSocket;",
    present: false,
  },
  {
    name: "awaited return enters finally",
    source:
      "(async () => { try { return await 0; } finally { new Socket('wss://example.test/review-phase'); } })(); const Socket = globalThis.WebSocket;",
    present: true,
  },
  {
    name: "throw before unreachable await",
    source:
      "(async () => { try { throw 0; await 0; } finally { new Socket('wss://example.test/review-phase'); } })(); const Socket = globalThis.WebSocket;",
    present: false,
  },
  {
    name: "throwing operand before await",
    source:
      "(async () => { try { throw (missing(), await 0); } finally { new Socket('wss://example.test/review-phase'); } })(); const Socket = globalThis.WebSocket;",
    present: false,
  },
  {
    name: "await before throwing operand",
    source:
      "(async () => { try { throw (await 0, missing()); } finally { new Socket('wss://example.test/review-phase'); } })(); const Socket = globalThis.WebSocket;",
    present: true,
  },
  {
    name: "nested promise projection",
    source:
      "export {}; const { box: { pending } } = { box: { pending: import('ws') } }; const { WebSocket: Socket } = await pending; new Socket('wss://example.test/review-phase');",
    present: true,
  },
  {
    name: "array promise projection",
    source:
      "export {}; const [pending] = [import('ws')]; const { WebSocket: Socket } = await pending; new Socket('wss://example.test/review-phase');",
    present: true,
  },
  {
    name: "getter promise stays unknown",
    source:
      "export {}; const { pending } = { get pending() { return import('ws') } }; const { WebSocket: Socket } = await pending; new Socket('wss://example.test/review-phase');",
    present: false,
  },
  {
    name: "changed iteration stays unknown",
    source:
      "export {}; Array.prototype[Symbol.iterator] = function* () { yield Promise.resolve({ WebSocket: class {} }); }; const [pending] = [import('ws')]; const { WebSocket: Socket } = await pending; new Socket('wss://example.test/review-phase');",
    present: false,
  },
  {
    name: "ordinary wrapper return",
    source:
      "(async () => { const pending = (async () => { await 0; new Socket('wss://example.test/review-phase'); })(); await (function () { return pending; })(); const Socket = globalThis.WebSocket; })();",
    present: false,
  },
  {
    name: "nested literal wrapper returns",
    source:
      "(async () => { const pending = (async () => { await 0; new Socket('wss://example.test/review-phase'); })(); await (() => (() => pending)())(); const Socket = globalThis.WebSocket; })();",
    present: false,
  },
  {
    name: "forward wrapper alias is not initialized",
    source:
      "(async () => { try { await (() => pending)(); } catch {} const pending = (async () => { await 0; new Socket('wss://example.test/review-phase'); })(); const Socket = globalThis.WebSocket; })();",
    present: true,
  },
  {
    name: "JSX attribute suspension",
    source:
      "(async () => { <div value={await ready} />; new Socket('wss://example.test/review-phase'); })(); const Socket = globalThis.WebSocket;",
    present: true,
  },
  {
    name: "JSX fragment suspension",
    source:
      "(async () => { <><div />{await ready}</>; new Socket('wss://example.test/review-phase'); })(); const Socket = globalThis.WebSocket;",
    present: true,
  },
  {
    name: "JSX spread suspension",
    source:
      "(async () => { <div {...await ready} />; new Socket('wss://example.test/review-phase'); })(); const Socket = globalThis.WebSocket;",
    present: true,
  },
  {
    name: "JSX stored function does not suspend",
    source:
      "(async () => { <div>{async () => await ready}</div>; new Socket('wss://example.test/review-phase'); })(); const Socket = globalThis.WebSocket;",
    present: false,
  },
  {
    name: "static auto accessor is eager",
    source:
      "const Client = class { static accessor socket = new Socket('wss://example.test/review-phase') }; const Socket = globalThis.WebSocket;",
    present: false,
  },
  {
    name: "immediate auto accessor construction",
    source:
      "new (class { accessor socket = new Socket('wss://example.test/review-phase') })(); const Socket = globalThis.WebSocket;",
    present: false,
  },
  {
    name: "private auto accessor is deferred",
    source:
      "const Client = class { accessor #socket = new Socket('wss://example.test/review-phase') }; const Socket = globalThis.WebSocket; new Client();",
    present: true,
  },
];

describe("web bundle exact returned promises and class phases", () => {
  it.each(exactReturnedPromiseAndClassPhaseCases)(
    "preserves $name in both source consumers",
    ({ source, present }) => {
      const values = socketEndpoints(source).map((items) =>
        items.map((item) => item.value),
      );
      const expected = present ? ["wss://example.test/review-phase"] : [];
      expect(values).toEqual([expected, expected]);
    },
  );
});

const freshReadAndIterationCases = [
  [
    "object getter call",
    '({ get run() { new Socket("wss://example.test/fresh-read"); return () => {}; } }).run();',
    false,
  ],
  [
    "object getter read",
    'void ({ get run() { new Socket("wss://example.test/fresh-read"); return () => {}; } }).run;',
    false,
  ],
  [
    "paired getter and setter",
    'void ({ get run() { new Socket("wss://example.test/fresh-read"); }, set run(value) {} }).run;',
    false,
  ],
  [
    "static getter read",
    'void (class { static get run() { new Socket("wss://example.test/fresh-read"); } }).run;',
    false,
  ],
  [
    "fresh instance method",
    '(new (class { run() { new Socket("wss://example.test/fresh-read"); } })()).run();',
    false,
  ],
  [
    "fresh instance getter",
    'void (new (class { get run() { new Socket("wss://example.test/fresh-read"); } })()).run;',
    false,
  ],
  [
    "fresh instance function field",
    '(new (class { run = () => new Socket("wss://example.test/fresh-read"); })()).run();',
    false,
  ],
  [
    "instance method shadowed by field",
    '(new (class { run() { new Socket("wss://example.test/fresh-read"); } run = () => {}; })()).run();',
    true,
  ],
  [
    "stored instance method",
    'const run = (new (class { run() { new Socket("wss://example.test/fresh-read"); } })()).run;',
    true,
  ],
  [
    "synchronous generator for-of",
    'for (const ignored of (function* () { new Socket("wss://example.test/fresh-read"); yield 0; })()) {}',
    false,
  ],
  [
    "synchronous generator after yield",
    'for (const ignored of (function* () { yield 0; new Socket("wss://example.test/fresh-read"); })()) {}',
    false,
  ],
  [
    "getter precedes awaited call argument",
    '(async () => { ({ get run() { new Socket("wss://example.test/fresh-read"); return () => {}; } }).run(await 0); })();',
    false,
  ],
  [
    "method follows awaited call argument",
    '(async () => { (new (class { run() { new Socket("wss://example.test/fresh-read"); } })()).run(await 0); })();',
    true,
  ],
  [
    "generator consumer awaits between steps",
    '(async () => { for (const ignored of (function* () { yield 0; new Socket("wss://example.test/fresh-read"); })()) { await 0; } })();',
    true,
  ],
  [
    "generator consumer conditionally awaits",
    '(async () => { for (const ignored of (function* () { yield 0; new Socket("wss://example.test/fresh-read"); })()) { if (condition) await 0; } })();',
    true,
  ],
  [
    "async generator first step",
    '(async () => { for await (const ignored of (async function* () { new Socket("wss://example.test/fresh-read"); yield 0; })()) {} })();',
    false,
  ],
  [
    "generator consumer yields between steps",
    '(function* () { for (const ignored of (function* () { yield 0; new Socket("wss://example.test/fresh-read"); })()) { yield 0; } })().next();',
    true,
  ],
  [
    "generator consumer pattern awaits",
    '(async () => { for (const [value = await 0] of (function* () { yield []; new Socket("wss://example.test/fresh-read"); })()) {} })();',
    true,
  ],
  [
    "getter returned callable",
    '({ get run() { return () => new Socket("wss://example.test/fresh-read"); } }).run();',
    false,
  ],
  [
    "stored getter returned callable",
    'const run = ({ get run() { return () => new Socket("wss://example.test/fresh-read"); } }).run;',
    true,
  ],
  [
    "getter returned callable follows awaited argument",
    '(async () => { ({ get run() { return () => new Socket("wss://example.test/fresh-read"); } }).run(await 0); })();',
    true,
  ],
  [
    "unresumed generator",
    '(function* () { new Socket("wss://example.test/fresh-read"); yield 0; })();',
    true,
  ],
] as const;

describe("fresh member reads and synchronous generator consumption", () => {
  it.each(freshReadAndIterationCases)(
    "preserves %s in both source consumers",
    (_name, prefix, present) => {
      const source = `${prefix} const Socket = globalThis.WebSocket;`;
      const expected = present ? ["wss://example.test/fresh-read"] : [];
      expect(
        socketEndpoints(source).map((items) => items.map(({ value }) => value)),
      ).toEqual([expected, expected]);
    },
  );
});

const completionReviewCases = [
  {
    name: "immutable assignment",
    source:
      'const holder = 0; new (holder = globalThis.WebSocket)("wss://example.test/review-latest");',
    present: false,
  },
  {
    name: "spread generator",
    source:
      '[...(function* () { new Socket("wss://example.test/review-latest"); yield 0; })()]; const Socket = globalThis.WebSocket;',
    present: false,
  },
  {
    name: "caught prefix skips wait",
    source:
      '(async () => { const pending = (async () => { await ready; new Socket("wss://example.test/review-latest"); })(); try { null.value; await pending; } catch {} const Socket = globalThis.WebSocket; })();',
    present: true,
  },
  {
    name: "with body suspension",
    source:
      '(async () => { with ({}) { await ready; } new Socket("wss://example.test/review-latest"); })(); const Socket = globalThis.WebSocket;',
    present: true,
  },
  {
    name: "global self member",
    source:
      'new globalThis.globalThis.WebSocket("wss://example.test/review-latest");',
    present: true,
  },
  {
    name: "computed expression key before value write",
    source:
      'const ws = require("ws"); const object = { [new ws.WebSocket("wss://example.test/review-latest")]: (ws.WebSocket = class {}) };',
    present: true,
  },
  {
    name: "async disposal between yields",
    source:
      '(async () => { for (const item of (function* () { yield 0; new Socket("wss://example.test/review-latest"); })()) { await using resource = null; } })(); const Socket = globalThis.WebSocket;',
    present: true,
  },
  {
    name: "mutable let assignment",
    source:
      'let holder; new (holder = globalThis.WebSocket)("wss://example.test/review-latest");',
    present: true,
  },
  {
    name: "hoisted var assignment",
    source:
      'new (holder = globalThis.WebSocket)("wss://example.test/review-latest"); var holder;',
    present: true,
  },
  {
    name: "lexical assignment before initialization",
    source:
      'new (holder = globalThis.WebSocket)("wss://example.test/review-latest"); let holder;',
    present: false,
  },
  {
    name: "readonly selected object assignment",
    source:
      'const holder = 0; const { WebSocket: Socket } = (holder = globalThis); new Socket("wss://example.test/review-latest");',
    present: false,
  },
  {
    name: "mutable selected object assignment",
    source:
      'let holder; const { WebSocket: Socket } = (holder = globalThis); new Socket("wss://example.test/review-latest");',
    present: true,
  },
  {
    name: "unproven setter assignment",
    source:
      'const holder = { set socket(value) { throw 0; } }; new (holder.socket = globalThis.WebSocket)("wss://example.test/review-latest");',
    present: false,
  },
  {
    name: "spread generator after yield",
    source:
      '[...(function* () { yield 0; new Socket("wss://example.test/review-latest"); })()]; const Socket = globalThis.WebSocket;',
    present: false,
  },
  {
    name: "call spread generator",
    source:
      'consume(...(function* () { yield 0; new Socket("wss://example.test/review-latest"); })()); const Socket = globalThis.WebSocket;',
    present: false,
  },
  {
    name: "construct spread generator",
    source:
      'new Target(...(function* () { new Socket("wss://example.test/review-latest"); yield 0; })()); const Socket = globalThis.WebSocket;',
    present: false,
  },
  {
    name: "object spread does not iterate",
    source:
      '({...(function* () { new Socket("wss://example.test/review-latest"); yield 0; })()}); const Socket = globalThis.WebSocket;',
    present: true,
  },
  {
    name: "stored generator after initialization",
    source:
      'const iterator = (function* () { yield 0; new Socket("wss://example.test/review-latest"); })(); const Socket = globalThis.WebSocket; [...iterator];',
    present: true,
  },
  {
    name: "sync disposal does not suspend",
    source:
      '(async () => { for (const item of (function* () { yield 0; new Socket("wss://example.test/review-latest"); })()) { using resource = null; } })(); const Socket = globalThis.WebSocket;',
    present: false,
  },
  {
    name: "async disposal cannot delay first yield",
    source:
      '(async () => { for (const item of (function* () { new Socket("wss://example.test/review-latest"); yield 0; })()) { await using resource = null; } })(); const Socket = globalThis.WebSocket;',
    present: false,
  },
  {
    name: "stored async disposal does not suspend",
    source:
      '(async () => { for (const item of (function* () { yield 0; new Socket("wss://example.test/review-latest"); })()) { const later = async () => { await using resource = null; }; } })(); const Socket = globalThis.WebSocket;',
    present: false,
  },
  {
    name: "with no suspension",
    source:
      '(async () => { with ({}) { 0; } new Socket("wss://example.test/review-latest"); })(); const Socket = globalThis.WebSocket;',
    present: false,
  },
  {
    name: "with stored async function",
    source:
      '(async () => { with ({}) { const later = async () => await ready; } new Socket("wss://example.test/review-latest"); })(); const Socket = globalThis.WebSocket;',
    present: false,
  },
  {
    name: "repeated global self path",
    source:
      'new globalThis.globalThis.globalThis.WebSocket("wss://example.test/review-latest");',
    present: true,
  },
  {
    name: "self path constructor capture",
    source:
      'const Socket = globalThis.self.globalThis.WebSocket; new Socket("wss://example.test/review-latest");',
    present: true,
  },
  {
    name: "shadowed global self path",
    source:
      'const globalThis = {globalThis: {WebSocket: class {}}}; new globalThis.globalThis.WebSocket("wss://example.test/review-latest");',
    present: false,
  },
  {
    name: "overwritten global self path",
    source:
      'globalThis.globalThis.WebSocket = class {}; new globalThis.globalThis.WebSocket("wss://example.test/review-latest");',
    present: false,
  },
  {
    name: "overwritten self reference",
    source:
      'globalThis.self = {WebSocket: class {}}; new globalThis.self.WebSocket("wss://example.test/review-latest");',
    present: false,
  },
  {
    name: "arbitrary global property",
    source:
      'new globalThis.custom.WebSocket("wss://example.test/review-latest");',
    present: false,
  },
  {
    name: "computed key after earlier write",
    source:
      'const ws = require("ws"); const object = { [(ws.WebSocket = class {})]: new ws.WebSocket("wss://example.test/review-latest") };',
    present: false,
  },
  {
    name: "computed key keeps earlier capture",
    source:
      'const ws = require("ws"); const Socket = ws.WebSocket; const object = { [new Socket("wss://example.test/review-latest")]: (ws.WebSocket = class {}) };',
    present: true,
  },
  {
    name: "nonthrowing caught prefix still waits",
    source:
      '(async () => { const pending = (async () => { await ready; new Socket("wss://example.test/review-latest"); })(); try { 0; await pending; } catch {} const Socket = globalThis.WebSocket; })();',
    present: false,
  },
  {
    name: "caught sequence prefix skips wait",
    source:
      '(async () => { const pending = (async () => { await ready; new Socket("wss://example.test/review-latest"); })(); try { (null.value, await pending); } catch {} const Socket = globalThis.WebSocket; })();',
    present: true,
  },
  {
    name: "caught await operand skips wait",
    source:
      '(async () => { const pending = (async () => { await ready; new Socket("wss://example.test/review-latest"); })(); try { await (null.value, pending); } catch {} const Socket = globalThis.WebSocket; })();',
    present: true,
  },
  {
    name: "stored function prefix cannot throw",
    source:
      '(async () => { const pending = (async () => { await ready; new Socket("wss://example.test/review-latest"); })(); try { const later = () => null.value; await pending; } catch {} const Socket = globalThis.WebSocket; })();',
    present: false,
  },
];

describe("web bundle completed writes and consumer suspension", () => {
  it.each(completionReviewCases)(
    "preserves $name in both consumers",
    ({ source, present }) => {
      const expected = present ? ["wss://example.test/review-latest"] : [];
      expect(
        socketEndpoints(source).map((items) => items.map((item) => item.value)),
      ).toEqual([expected, expected]);
    },
  );
});

const scopeExitReviewCases = [
  {
    name: "block disposal",
    source:
      '(async () => { { await using resource = null; } new Socket("wss://example.test/review-scope"); })(); const Socket = globalThis.WebSocket;',
    present: true,
  },
  {
    name: "producer created in caught block",
    source:
      'export {}; try { const pending = (async () => { await 0; new Socket("wss://example.test/review-scope"); })(); await pending; const Socket = globalThis.WebSocket; } catch {}',
    present: false,
  },
  {
    name: "outer mutable assignment invocation",
    source:
      'let connect; (() => { (connect = () => new Socket("wss://example.test/review-scope"))(); })(); const Socket = globalThis.WebSocket;',
    present: false,
  },
  {
    name: "loop head assignment",
    source:
      'for (let holder of [new (holder = globalThis.WebSocket)("wss://example.test/review-scope")]) {}',
    present: false,
  },
  {
    name: "destructuring generator",
    source:
      'const [ignored] = (function* () { new Socket("wss://example.test/review-scope"); yield 0; })(); const Socket = globalThis.WebSocket;',
    present: false,
  },
  {
    name: "selected switch test suspension",
    source:
      '(async () => { switch (kind) { case await ready: new Socket("wss://example.test/review-scope"); } })(); const Socket = globalThis.WebSocket;',
    present: true,
  },
  {
    name: "optional literal arguments",
    source:
      '(async () => { (async (_x) => { new Socket("wss://example.test/review-scope"); })?.(await ready); })(); const Socket = globalThis.WebSocket;',
    present: true,
  },
  {
    name: "disposal has not exited",
    source:
      '(async()=>{await using resource=null;new Socket("wss://example.test/review-scope")})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "synchronous block disposal",
    source:
      '(async()=>{{using resource=null;}new Socket("wss://example.test/review-scope")})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "stored disposal scope",
    source:
      '(async()=>{const later=async()=>{await using resource=null;};new Socket("wss://example.test/review-scope")})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "skipped disposal block",
    source:
      '(async()=>{if(false){await using resource=null;}new Socket("wss://example.test/review-scope")})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "taken disposal block",
    source:
      '(async()=>{if(true){await using resource=null;}new Socket("wss://example.test/review-scope")})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "throw before same-block producer",
    source:
      'export {};try{null.value;const pending=(async()=>{await 0;new Socket("wss://example.test/review-scope")})();await pending;const Socket=globalThis.WebSocket;}catch{}',
    present: false,
  },
  {
    name: "throw after same-block producer",
    source:
      'export {};try{const pending=(async()=>{await 0;new Socket("wss://example.test/review-scope")})();null.value;await pending;}catch{}const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "throw after producer in same declaration",
    source:
      'export {};try{const pending=(async()=>{await 0;new Socket("wss://example.test/review-scope")})(), tail=null.value;await pending;}catch{}const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "safe prefix before same-block producer",
    source:
      'export {};try{0;const pending=(async()=>{await 0;new Socket("wss://example.test/review-scope")})();await pending;const Socket=globalThis.WebSocket;}catch{}',
    present: false,
  },
  {
    name: "outer var assignment invocation",
    source:
      'var connect;(()=>{(connect=()=>new Socket("wss://example.test/review-scope"))()})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "outer let assignment after alias initialization",
    source:
      'const Socket=globalThis.WebSocket;let connect;(()=>{(connect=()=>new Socket("wss://example.test/review-scope"))()})();',
    present: true,
  },
  {
    name: "for-in loop head assignment",
    source:
      'for(let holder in { [new(holder=globalThis.WebSocket)("wss://example.test/review-scope")]:0}){}',
    present: false,
  },
  {
    name: "var loop head assignment",
    source:
      'for(var holder of [new(holder=globalThis.WebSocket)("wss://example.test/review-scope")]){}',
    present: true,
  },
  {
    name: "initialized loop body assignment",
    source:
      'for(let holder of [0]){new(holder=globalThis.WebSocket)("wss://example.test/review-scope")}',
    present: true,
  },
  {
    name: "array hole consumes first resume",
    source:
      'const [,ignored]=(function*(){new Socket("wss://example.test/review-scope");yield 0})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "assignment pattern consumes generator",
    source:
      'let ignored;[ignored]=(function*(){new Socket("wss://example.test/review-scope");yield 0})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "rest pattern drains generator",
    source:
      'const [...ignored]=(function*(){yield 0;new Socket("wss://example.test/review-scope")})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "two pattern elements resume in same turn",
    source:
      'const [a,b]=(function*(){yield 0;new Socket("wss://example.test/review-scope");yield 1})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "empty array pattern only closes iterator",
    source:
      'const []=(function*(){new Socket("wss://example.test/review-scope");yield 0})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "object pattern does not iterate",
    source:
      'const {}=(function*(){new Socket("wss://example.test/review-scope");yield 0})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "stored generator consumed after alias",
    source:
      'const iterator=(function*(){new Socket("wss://example.test/review-scope");yield 0})();const Socket=globalThis.WebSocket;const [ignored]=iterator;',
    present: true,
  },
  {
    name: "pattern default can suspend before next resume",
    source:
      '(async()=>{const [a=await ready,b]=(function*(){yield undefined;new Socket("wss://example.test/review-scope");yield 1})()})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "switch fallthrough skips selected test",
    source:
      '(async()=>{switch(kind){case 0:case await ready:new Socket("wss://example.test/review-scope")}})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "switch predecessor break prevents fallthrough",
    source:
      '(async()=>{switch(kind){case 0:break;case await ready:new Socket("wss://example.test/review-scope")}})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "optional literal call without argument wait",
    source:
      '(async()=>{(async x=>{new Socket("wss://example.test/review-scope")})?.(0)})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "optional argument stores an async function",
    source:
      '(async()=>{(async x=>{new Socket("wss://example.test/review-scope")})?.(async()=>await ready)})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "skipped optional arguments do not suspend siblings",
    source:
      '(async()=>{null?.(await ready);new Socket("wss://example.test/review-scope")})();const Socket=globalThis.WebSocket;',
    present: false,
  },
];
describe("web bundle scope exit and relative producer order", () => {
  it.each(scopeExitReviewCases)(
    "preserves $name in both consumers",
    ({ source, present }) => {
      const expected = present ? ["wss://example.test/review-scope"] : [];
      expect(
        socketEndpoints(source).map((items) => items.map((item) => item.value)),
      ).toEqual([expected, expected]);
    },
  );
});

const consumptionReviewCases = [
  {
    name: "later pattern default",
    source:
      '(async()=>{const [a,b=await 0,c]=(function*(){yield 0;new Socket("wss://example.test/review-consumption");yield undefined;yield 2})()})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "getter write target",
    source:
      '({get run(){new Socket("wss://example.test/review-consumption")}}).run=0;const Socket=globalThis.WebSocket;',
    present: true,
    runtimePresent: false,
  },
  {
    name: "throwing sequence prefix",
    source:
      'new(null.value,globalThis.WebSocket)("wss://example.test/review-consumption");',
    present: false,
  },
  {
    name: "optional call sibling",
    source:
      '(async()=>{(()=>{})?.(await ready);new Socket("wss://example.test/review-consumption")})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "conditional break bypass",
    source:
      '(async()=>{const pending=(async()=>{await ready;new Socket("wss://example.test/review-consumption")})();while(true){if(skip)break;await pending;break;}const Socket=globalThis.WebSocket;})();',
    present: true,
  },
  {
    name: "async wrapper adoption",
    source:
      '(async()=>{const pending=(async()=>{await ready;new Socket("wss://example.test/review-consumption")})();await(async()=>pending)();const Socket=globalThis.WebSocket;})();',
    present: false,
  },
  {
    name: "resumed generator delegate",
    source:
      '(function*(){yield*(function*(){new Socket("wss://example.test/review-consumption");yield 0})()})().next();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "earlier selected default",
    source:
      '(async()=>{const [a=await 0,b]=(function*(){yield undefined;new Socket("wss://example.test/review-consumption");yield 1})()})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "unselected earlier default",
    source:
      '(async()=>{const [a=await 0,b]=(function*(){yield 0;new Socket("wss://example.test/review-consumption");yield 1})()})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "first resume before default",
    source:
      '(async()=>{const [a=await 0]=(function*(){new Socket("wss://example.test/review-consumption");yield undefined})()})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "stored async default does not suspend",
    source:
      '(async()=>{const [a=async()=>await 0,b]=(function*(){yield undefined;new Socket("wss://example.test/review-consumption");yield 1})()})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "argumentless yield selects default",
    source:
      '(async()=>{const [a=await 0,b]=(function*(){yield;new Socket("wss://example.test/review-consumption");yield 1})()})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "selected default before rest drain",
    source:
      '(async()=>{const [a=await 0,...rest]=(function*(){yield undefined;yield 0;new Socket("wss://example.test/review-consumption")})()})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "getter direct read",
    source:
      '({get run(){new Socket("wss://example.test/review-consumption")}}).run;const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "getter compound write reads first",
    source:
      '({get run(){new Socket("wss://example.test/review-consumption")}}).run+=0;const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "getter delete target",
    source:
      'delete({get run(){new Socket("wss://example.test/review-consumption")}}).run;const Socket=globalThis.WebSocket;',
    present: true,
    runtimePresent: false,
  },
  {
    name: "getter destructuring write",
    source:
      '[({get run(){new Socket("wss://example.test/review-consumption")}}).run]=[0];const Socket=globalThis.WebSocket;',
    present: true,
    runtimePresent: false,
  },
  {
    name: "getter nested receiver is read",
    source:
      '({get run(){new Socket("wss://example.test/review-consumption")}}).run.value=0;const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "getter optional delete target",
    source:
      'delete({get run(){new Socket("wss://example.test/review-consumption")}})?.run;const Socket=globalThis.WebSocket;',
    present: true,
    runtimePresent: false,
  },
  {
    name: "literal sequence prefix",
    source:
      'new(0,globalThis.WebSocket)("wss://example.test/review-consumption");',
    present: true,
  },
  {
    name: "inert function sequence prefix",
    source:
      'new(()=>0,globalThis.WebSocket)("wss://example.test/review-consumption");',
    present: true,
  },
  {
    name: "nested throwing sequence",
    source:
      'const Socket=(0,(null.value,globalThis.WebSocket));new Socket("wss://example.test/review-consumption");',
    present: false,
  },
  {
    name: "projected throwing sequence",
    source:
      'const {WebSocket:Socket}=(null.value,globalThis);new Socket("wss://example.test/review-consumption");',
    present: false,
  },
  {
    name: "void literal sequence prefix",
    source:
      'new(void 0,globalThis.WebSocket)("wss://example.test/review-consumption");',
    present: true,
  },
  {
    name: "null optional sibling skips arguments",
    source:
      '(async()=>{null?.(await ready);new Socket("wss://example.test/review-consumption")})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "stored optional async argument",
    source:
      '(async()=>{(()=>{})?.(async()=>await ready);new Socket("wss://example.test/review-consumption")})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "ordinary literal awaited argument",
    source:
      '(async()=>{(()=>{})(await ready);new Socket("wss://example.test/review-consumption")})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "conditional labeled break bypass",
    source:
      '(async()=>{const pending=(async()=>{await ready;new Socket("wss://example.test/review-consumption")})();outer:{if(skip)break outer;await pending;}const Socket=globalThis.WebSocket;})();',
    present: true,
  },
  {
    name: "break before producer does not bypass its wait",
    source:
      '(async()=>{while(true){if(skip)break;const pending=(async()=>{await ready;new Socket("wss://example.test/review-consumption")})();await pending;const Socket=globalThis.WebSocket;break;}})();',
    present: false,
  },
  {
    name: "literal false break retains mandatory wait",
    source:
      '(async()=>{const pending=(async()=>{await ready;new Socket("wss://example.test/review-consumption")})();while(true){if(false)break;await pending;break;}const Socket=globalThis.WebSocket;})();',
    present: false,
  },
  {
    name: "nested loop owns its break",
    source:
      '(async()=>{const pending=(async()=>{await ready;new Socket("wss://example.test/review-consumption")})();while(true){break;}await pending;const Socket=globalThis.WebSocket;})();',
    present: false,
  },
  {
    name: "async block wrapper adoption",
    source:
      '(async()=>{const pending=(async()=>{await ready;new Socket("wss://example.test/review-consumption")})();await(async()=>{return pending})();const Socket=globalThis.WebSocket;})();',
    present: false,
  },
  {
    name: "async return await adoption",
    source:
      '(async()=>{const pending=(async()=>{await ready;new Socket("wss://example.test/review-consumption")})();await(async()=>await pending)();const Socket=globalThis.WebSocket;})();',
    present: false,
  },
  {
    name: "nested async wrapper adoption",
    source:
      '(async()=>{const pending=(async()=>{await ready;new Socket("wss://example.test/review-consumption")})();await(async()=>(async()=>pending)())();const Socket=globalThis.WebSocket;})();',
    present: false,
  },
  {
    name: "unawaited wrapper does not block",
    source:
      '(async()=>{const pending=(async()=>{await ready;new Socket("wss://example.test/review-consumption")})();(async()=>pending)();const Socket=globalThis.WebSocket;})();',
    present: true,
  },
  {
    name: "unrelated wrapper does not adopt producer",
    source:
      '(async()=>{const pending=(async()=>{await ready;new Socket("wss://example.test/review-consumption")})();await(async()=>0)();const Socket=globalThis.WebSocket;})();',
    present: true,
  },
  {
    name: "async generator wrapper is not a promise adoption",
    source:
      '(async()=>{const pending=(async()=>{await ready;new Socket("wss://example.test/review-consumption")})();await(async function*(){return pending})();const Socket=globalThis.WebSocket;})();',
    present: true,
  },
  {
    name: "delegate consumed by spread",
    source:
      '[...(function*(){yield*(function*(){new Socket("wss://example.test/review-consumption");yield 0})()})()];const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "delegate drain after inner yield",
    source:
      '[...(function*(){yield*(function*(){yield 0;new Socket("wss://example.test/review-consumption")})()})()];const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "stored delegate after alias initialization",
    source:
      'const iterator=(function*(){yield*(function*(){new Socket("wss://example.test/review-consumption");yield 0})()})();const Socket=globalThis.WebSocket;iterator.next();',
    present: true,
  },
  {
    name: "async delegate first step",
    source:
      '(async function*(){yield*(function*(){new Socket("wss://example.test/review-consumption");yield 0})()})().next();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "async delegate later step",
    source:
      '(async function*(){yield*(function*(){yield 0;new Socket("wss://example.test/review-consumption");yield 1})()})().next();const Socket=globalThis.WebSocket;',
    present: true,
    runtimePresent: false,
  },
  {
    name: "initialized prefix read",
    source:
      'const value=0;new(value,globalThis.WebSocket)("wss://example.test/review-consumption");',
    present: true,
  },
  {
    name: "mutable prefix assignment",
    source:
      'let value;new(value=0,globalThis.WebSocket)("wss://example.test/review-consumption");',
    present: true,
  },
  {
    name: "immutable prefix assignment",
    source:
      'const value=0;new(value=1,globalThis.WebSocket)("wss://example.test/review-consumption");',
    present: false,
  },
] as const;
describe("web bundle consumed prefixes and settlement dependencies", () => {
  it.each(consumptionReviewCases)(
    "preserves $name in both consumers",
    ({ source, present }) => {
      const expected = present ? ["wss://example.test/review-consumption"] : [];
      expect(
        socketEndpoints(source).map((items) => items.map((item) => item.value)),
      ).toEqual([expected, expected]);
    },
  );
});

const phaseReviewCases = [
  {
    name: "inherited object value does not select a default",
    source:
      'Object.prototype.x=1;(async()=>{const [{x=await 0},next]=(function*(){yield {};new Socket("wss://example.test/review-phases");yield 1;})();})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "inherited array hole value does not select a default",
    source:
      'Array.prototype[0]=1;(async()=>{const [[x=await 0],next]=(function*(){yield [,];new Socket("wss://example.test/review-phases");yield 1;})();})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "setter for-of target",
    source:
      'for(({set run(value){new Socket("wss://example.test/review-phases");}}).run of [0]){}const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "setter for-await target",
    source:
      '(async()=>{for await(({set run(value){new Socket("wss://example.test/review-phases");}}).run of [0]){}})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "shadowed class setter metadata",
    source:
      '(class{static set run(value){new Socket("wss://example.test/review-phases");}static run=0;}).run=1;const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "immediate sequence with a call prefix",
    source:
      '((()=>0)(),()=>new Socket("wss://example.test/review-phases"))();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "nested computed pattern wait",
    source:
      '(async()=>{const [{[await 0]:value},next]=(function*(){yield {};new Socket("wss://example.test/review-phases");yield 1;})();})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "fresh setter write",
    source:
      '({set run(value){new Socket("wss://example.test/review-phases");}}).run=0;const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "disposal before finalizer",
    source:
      '(async()=>{try{await using resource=null;}finally{new Socket("wss://example.test/review-phases");}})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "hoisted function prefix",
    source:
      'function marker(){};new(marker,globalThis.WebSocket)("wss://example.test/review-phases");',
    present: true,
  },
  {
    name: "safe try await before catch completion",
    source:
      '(async()=>{try{await 0;}catch{}new Socket("wss://example.test/review-phases");})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "do await before break",
    source:
      '(async()=>{do{await 0;break;}while(false);new Socket("wss://example.test/review-phases");})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "disposal before consumed label break",
    source:
      '(async()=>{exit:{await using r=null;break exit;}new Socket("wss://example.test/review-phases");})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "computed setter write",
    source:
      '({set ["run"](value){new Socket("wss://example.test/review-phases");}})["run"]=0;const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "paired setter after getter",
    source:
      '({get run(){return 0;},set run(value){new Socket("wss://example.test/review-phases");}}).run=0;const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "paired setter before getter",
    source:
      '({set run(value){new Socket("wss://example.test/review-phases");},get run(){return 0;}}).run=0;const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "static class setter",
    source:
      '(class{static set run(value){new Socket("wss://example.test/review-phases");}}).run=0;const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "instance class setter",
    source:
      '(new(class{set run(value){new Socket("wss://example.test/review-phases");}})).run=0;const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "class paired setter",
    source:
      '(class{static set run(value){new Socket("wss://example.test/review-phases");}static get run(){return 0;}}).run=0;const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "compound setter write",
    source:
      '({get run(){return 0;},set run(value){new Socket("wss://example.test/review-phases");}}).run+=1;const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "update setter write",
    source:
      '({get run(){return 0;},set run(value){new Socket("wss://example.test/review-phases");}}).run++;const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "destructuring setter write",
    source:
      '[({set run(value){new Socket("wss://example.test/review-phases");}}).run]=[0];const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "setter after awaited RHS",
    source:
      '(async()=>{({set run(value){new Socket("wss://example.test/review-phases");}}).run=await 0;})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "setter before later pattern wait",
    source:
      '(async()=>{let b;[({set run(value){new Socket("wss://example.test/review-phases");}}).run,b=await 0]=[0,undefined];})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "setter after earlier pattern wait",
    source:
      '(async()=>{let a;[a=await 0,({set run(value){new Socket("wss://example.test/review-phases");}}).run]=[undefined,0];})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "setter-only read metadata",
    source:
      '({set run(value){new Socket("wss://example.test/review-phases");}}).run;const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "setter delete metadata",
    source:
      'delete({set run(value){new Socket("wss://example.test/review-phases");}}).run;const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "selected nested property default",
    source:
      '(async()=>{const [{x=await 0},next]=(function*(){yield {x:undefined};new Socket("wss://example.test/review-phases");yield 1;})();})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "unselected nested property default",
    source:
      '(async()=>{const [{x=await 0},next]=(function*(){yield {x:1};new Socket("wss://example.test/review-phases");yield 1;})();})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "selected nested array default",
    source:
      '(async()=>{const [[x=await 0],next]=(function*(){yield [undefined];new Socket("wss://example.test/review-phases");yield 1;})();})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "unselected nested array default",
    source:
      '(async()=>{const [[x=await 0],next]=(function*(){yield [1];new Socket("wss://example.test/review-phases");yield 1;})();})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "nested computed key after selected default",
    source:
      '(async()=>{const [{[await 0]:x}={},next]=(function*(){yield;new Socket("wss://example.test/review-phases");yield 1;})();})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "pattern wait after first generator read",
    source:
      '(async()=>{const [{[await 0]:x},next]=(function*(){new Socket("wss://example.test/review-phases");yield {};yield 1;})();})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "later nested pattern does not defer earlier resume",
    source:
      '(async()=>{const [a,{[await 0]:x}]=(function*(){yield 0;new Socket("wss://example.test/review-phases");yield {};})();})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "nested computed wait in inner pattern",
    source:
      '(async()=>{const [{a:{[await 0]:x}},next]=(function*(){yield {a:{}};new Socket("wss://example.test/review-phases");yield 1;})();})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "forward hoisted function prefix",
    source:
      'new(marker,globalThis.WebSocket)("wss://example.test/review-phases");function marker(){}',
    present: true,
  },
  {
    name: "lexical function expression prefix TDZ",
    source:
      'new(marker,globalThis.WebSocket)("wss://example.test/review-phases");const marker=()=>0;',
    present: false,
  },
  {
    name: "hoisted function prefix in invocation",
    source:
      '(()=>{new(marker,globalThis.WebSocket)("wss://example.test/review-phases");function marker(){}})();',
    present: true,
  },
  {
    name: "immediate call prefix followed by await",
    source:
      '(async()=>{((()=>0)(),()=>new Socket("wss://example.test/review-phases"))(await 0);})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "immediate call prefix with bind",
    source:
      '((()=>0)(),()=>new Socket("wss://example.test/review-phases")).bind(null)();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "safe try await before caught throw",
    source:
      '(async()=>{try{await 0;throw 1;}catch{}new Socket("wss://example.test/review-phases");})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "throw before caught dead await",
    source:
      '(async()=>{try{throw 1;await 0;}catch{}new Socket("wss://example.test/review-phases");})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "throwing operand before caught await",
    source:
      '(async()=>{try{null.value;await 0;}catch{}new Socket("wss://example.test/review-phases");})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "safe declaration before try await",
    source:
      '(async()=>{try{const value=0;await 0;}catch{}new Socket("wss://example.test/review-phases");})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "do break skips test wait",
    source:
      '(async()=>{do{break;}while(await 0);new Socket("wss://example.test/review-phases");})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "do break before dead await",
    source:
      '(async()=>{do{break;await 0;}while(false);new Socket("wss://example.test/review-phases");})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "do conditional break before await",
    source:
      '(async()=>{do{if(skip)break;await 0;}while(false);new Socket("wss://example.test/review-phases");})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "do await before continue",
    source:
      '(async()=>{do{await 0;continue;}while(false);new Socket("wss://example.test/review-phases");})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "disposal before do break",
    source:
      '(async()=>{do{await using r=null;break;}while(false);new Socket("wss://example.test/review-phases");})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "label break before disposal",
    source:
      '(async()=>{exit:{break exit;await using r=null;}new Socket("wss://example.test/review-phases");})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "synchronous disposal before label break",
    source:
      '(async()=>{exit:{using r=null;break exit;}new Socket("wss://example.test/review-phases");})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "nested disposal before label break",
    source:
      '(async()=>{exit:{{await using r=null;}break exit;}new Socket("wss://example.test/review-phases");})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "throwing prefix before finalizer disposal",
    source:
      '(async()=>{try{null.value;await using r=null;}finally{new Socket("wss://example.test/review-phases");}})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "throwing acquisition before finalizer",
    source:
      '(async()=>{try{await using r=null.value;}finally{new Socket("wss://example.test/review-phases");}})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "synchronous disposal before finalizer",
    source:
      '(async()=>{try{using r=null;}finally{new Socket("wss://example.test/review-phases");}})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "nested asynchronous disposal before finalizer",
    source:
      '(async()=>{try{{await using r=null;}}finally{new Socket("wss://example.test/review-phases");}})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "disposal before catch completion",
    source:
      '(async()=>{try{await using r=null;}catch{}new Socket("wss://example.test/review-phases");})();const Socket=globalThis.WebSocket;',
    present: true,
  },
] as const;
describe("web bundle executed phases and scope exits", () => {
  it.each(phaseReviewCases)(
    "preserves $name in both consumers",
    ({ source, present }) => {
      const expected = present ? ["wss://example.test/review-phases"] : [];
      expect(
        socketEndpoints(source).map((items) => items.map((item) => item.value)),
      ).toEqual([expected, expected]);
    },
  );
});

const iterationReviewCases = [
  {
    name: "identifier assignment immediate call",
    source:
      'let target;(target=()=>new Socket("wss://example.test/review-iteration"))();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "member assignment bound call",
    source:
      'const holder={};(holder.run=()=>new Socket("wss://example.test/review-iteration")).bind(null)();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "member assignment call member",
    source:
      'const holder={};(holder.run=()=>new Socket("wss://example.test/review-iteration")).call(null);const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "assignment constructor call",
    source:
      'const holder={};new(holder.run=function(){new Socket("wss://example.test/review-iteration");})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "assignment after awaited target key",
    source:
      'const holder={};(async()=>{(holder[await ready]=()=>new Socket("wss://example.test/review-iteration"))();})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "stored assignment callable metadata",
    source:
      'const holder={};holder.run=()=>new Socket("wss://example.test/review-iteration");const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "aliased prototype iterator skips default",
    source:
      'const proto=Array.prototype;proto[Symbol.iterator]=function*(){yield 1;};(async()=>{const [[x=await 0],next]=(function*(){yield [undefined];new Socket("wss://example.test/review-iteration");yield 1;})();})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "defined prototype iterator skips default",
    source:
      'Object.defineProperty(Array.prototype,Symbol.iterator,{value:function*(){yield 1;}});(async()=>{const [[x=await 0],next]=(function*(){yield [undefined];new Socket("wss://example.test/review-iteration");yield 1;})();})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "local Array lookalike does not taint iteration",
    source:
      'const Array={prototype:{}};Array.prototype[Symbol.iterator]=function*(){yield 1;};(async()=>{const [[x=await 0],next]=(function*(){yield [undefined];new Socket("wss://example.test/review-iteration");yield 1;})();})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "custom own iterator remains unknown",
    source:
      '(async()=>{const [[x=await 0],next]=(function*(){yield Object.assign([undefined],{[Symbol.iterator]:function*(){yield 1;}});new Socket("wss://example.test/review-iteration");yield 1;})();})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "mutated nested array remains unknown",
    source:
      '(async()=>{const [[x=await 0],next]=(function*(){yield ((a)=>{a[0]=1;return a;})([undefined]);new Socket("wss://example.test/review-iteration");yield 1;})();})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "exhausted second nested slot",
    source:
      '(async()=>{const [[x,y=await 0],next]=(function*(){yield [0];new Socket("wss://example.test/review-iteration");yield 1;})();})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "exhausted default after own undefined",
    source:
      '(async()=>{const [[x,y=await 0],next]=(function*(){yield [undefined];new Socket("wss://example.test/review-iteration");yield 1;})();})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "selected explicit nested default",
    source:
      '(async()=>{const [[x=await 0],next]=(function*(){yield [undefined];new Socket("wss://example.test/review-iteration");yield 1;})();})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "unselected explicit nested default",
    source:
      '(async()=>{const [[x=await 0],next]=(function*(){yield [1];new Socket("wss://example.test/review-iteration");yield 1;})();})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "rest default skipped",
    source:
      '(async()=>{let x;[...[x=await 0,({set run(v){new Socket("wss://example.test/review-iteration");}}).run]]=[1,0];})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "rest suffix preserves source offset",
    source:
      '(async()=>{let x,y;[y,...[x=await 0,({set run(v){new Socket("wss://example.test/review-iteration");}}).run]]=[99,undefined,0];})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "rest suffix does not use earlier slot",
    source:
      '(async()=>{let x,y;[y,...[x=await 0,({set run(v){new Socket("wss://example.test/review-iteration");}}).run]]=[undefined,99,0];})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "exhausted rest default before setter",
    source:
      '(async()=>{let x;[...[x=await 0,({set run(v){new Socket("wss://example.test/review-iteration");}}).run]]=[];})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "rest setter precedes later wait",
    source:
      '(async()=>{let x;[...[({set run(v){new Socket("wss://example.test/review-iteration");}}).run,x=await 0]]=[0,undefined];})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "nested rest pattern before setter",
    source:
      '(async()=>{let x;[...[[x=await 0],({set run(v){new Socket("wss://example.test/review-iteration");}}).run]]=[[undefined],0];})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "custom iterator skips rest default",
    source:
      'Array.prototype[Symbol.iterator]=function*(){yield 1;yield 0;};(async()=>{let x;[...[x=await 0,({set run(v){new Socket("wss://example.test/review-iteration");}}).run]]=[undefined,0];})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "rest drain precedes nested pattern wait",
    source:
      '(async()=>{const [...[x=await 0]]=(function*(){yield undefined;new Socket("wss://example.test/review-iteration");})();})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "arrow parameter consumes generator",
    source:
      '(([x])=>{})((function*(){new Socket("wss://example.test/review-iteration");yield 0;})());const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "constructor parameter consumes generator",
    source:
      'new(function([x]){})((function*(){new Socket("wss://example.test/review-iteration");yield 0;})());const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "async parameter consumes generator eagerly",
    source:
      '(async function([x]){})((function*(){new Socket("wss://example.test/review-iteration");yield 0;})());const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "generator parameter initializes on call",
    source:
      '(function*([x]){})((function*(){new Socket("wss://example.test/review-iteration");yield 0;})());const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "default parameter consumes supplied generator",
    source:
      '(function([x]=[]){} )((function*(){new Socket("wss://example.test/review-iteration");yield 0;})());const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "second positional parameter consumes generator",
    source:
      '(function(ignore,[x]){})(0,(function*(){new Socket("wss://example.test/review-iteration");yield 0;})());const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "later awaited argument precedes parameter consumption",
    source:
      '(async()=>{(function([x],ignored){} )((function*(){new Socket("wss://example.test/review-iteration");yield 0;})(),await ready);})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "parameter call member consumes generator",
    source:
      '(function([x]){}).call(null,(function*(){new Socket("wss://example.test/review-iteration");yield 0;})());const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "parameter apply member consumes generator",
    source:
      '(function([x]){}).apply(null,[(function*(){new Socket("wss://example.test/review-iteration");yield 0;})()]);const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "erased receiver annotation does not shift parameter",
    source:
      '(function(this:void,[x]){} )((function*(){new Socket("wss://example.test/review-iteration");yield 0;})());const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "optional literal call consumes parameter",
    source:
      '(function([x]){} )?.((function*(){new Socket("wss://example.test/review-iteration");yield 0;})());const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "non-consuming parameter retains metadata",
    source:
      '(function(x){} )((function*(){new Socket("wss://example.test/review-iteration");yield 0;})());const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "empty parameter pattern does not resume generator",
    source:
      '(function([]){} )((function*(){new Socket("wss://example.test/review-iteration");yield 0;})());const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "rest parameter alone does not resume generator",
    source:
      '(function(...[x]){} )((function*(){new Socket("wss://example.test/review-iteration");yield 0;})());const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "array optional receiver evaluates key",
    source:
      '(async()=>{[]?.[await ready];new Socket("wss://example.test/review-iteration");})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "number optional receiver evaluates key",
    source:
      '(async()=>{(0)?.[await ready];new Socket("wss://example.test/review-iteration");})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "function optional receiver evaluates key",
    source:
      '(async()=>{(function(){})?.[await ready];new Socket("wss://example.test/review-iteration");})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "null optional receiver skips key",
    source:
      '(async()=>{null?.[await ready];new Socket("wss://example.test/review-iteration");})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "void optional receiver skips key",
    source:
      '(async()=>{(void 0)?.[await ready];new Socket("wss://example.test/review-iteration");})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "nested optional chain retains mandatory first key",
    source:
      '(async()=>{({})?.[await ready]?.x;new Socket("wss://example.test/review-iteration");})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "constructed optional receiver evaluates key",
    source:
      '(async()=>{(new(class{}))?.[await ready];new Socket("wss://example.test/review-iteration");})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "member assignment immediate call",
    source:
      'const holder={};(holder.run=()=>new Socket("wss://example.test/review-iteration"))();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "custom nested array iterator skips default",
    source:
      'Array.prototype[Symbol.iterator]=function*(){yield 1;};(async()=>{const [[x=await 0],next]=(function*(){yield [undefined];new Socket("wss://example.test/review-iteration");yield 1;})();})();const Socket=globalThis.WebSocket;',
    present: false,
  },
  {
    name: "non-null optional member key",
    source:
      '(async()=>{({})?.[await ready];new Socket("wss://example.test/review-iteration");})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "exhausted nested array default",
    source:
      '(async()=>{const [[x=await 0],next]=(function*(){yield [];new Socket("wss://example.test/review-iteration");yield 1;})();})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "nested array rest setter target",
    source:
      '(async()=>{let x;[...[x=await 0,({set run(v){new Socket("wss://example.test/review-iteration");}}).run]]=[undefined,0];})();const Socket=globalThis.WebSocket;',
    present: true,
  },
  {
    name: "literal parameter consumes generator",
    source:
      '(function([x]){})((function*(){new Socket("wss://example.test/review-iteration");yield 0;})());const Socket=globalThis.WebSocket;',
    present: false,
  },
] as const;
const invocationReviewCases = [
  [
    "mandatory branching catch wait",
    "(async()=>{try{if(flag)throw 0;else throw 1;}catch{await 0;}new Socket(URL);})();const Socket=globalThis.WebSocket;",
    true,
  ],
  [
    "catch return skips unreachable wait",
    "(async()=>{try{throw 0;}catch{return;await 0;}finally{new Socket(URL);}})();const Socket=globalThis.WebSocket;",
    false,
  ],
  [
    "catch throw skips unreachable wait",
    "(async()=>{try{throw 0;}catch{throw 1;await 0;}finally{new Socket(URL);}})();const Socket=globalThis.WebSocket;",
    false,
  ],
  [
    "throwing catch binding skips wait",
    "(async()=>{try{throw null;}catch({}){await 0;}finally{new Socket(URL);}})();const Socket=globalThis.WebSocket;",
    false,
  ],
  [
    "nullish object rest blocks later wait",
    "(async()=>{const [{...x},y=await 0,next]=(function*(){yield null;yield undefined;new Socket(URL);})();})();const Socket=globalThis.WebSocket;",
    false,
  ],
  [
    "void object pattern key",
    "(async()=>{const [{[await 0]:x},next]=(function*(){yield void 0;new Socket(URL);})();})();const Socket=globalThis.WebSocket;",
    false,
  ],
  [
    "wrapped class constructor parameter",
    "new(0,class{constructor([x]){}})((function*(){new Socket(URL);yield 0;})());const Socket=globalThis.WebSocket;",
    false,
  ],
  [
    "optional fresh method parameter",
    "({run([x]){}})?.run?.((function*(){new Socket(URL);yield 0;})());const Socket=globalThis.WebSocket;",
    false,
  ],
  [
    "class constructor parameter",
    "new(class{constructor([x]){}})((function*(){new Socket(URL);yield 0;})());const Socket=globalThis.WebSocket;",
    false,
  ],
  [
    "object method parameter",
    "({run([x]){}}).run((function*(){new Socket(URL);yield 0;})());const Socket=globalThis.WebSocket;",
    false,
  ],
  [
    "class static method parameter",
    "(class{static run([x]){}}).run((function*(){new Socket(URL);yield 0;})());const Socket=globalThis.WebSocket;",
    false,
  ],
  [
    "fresh instance method parameter",
    "(new(class{run([x]){}})()).run((function*(){new Socket(URL);yield 0;})());const Socket=globalThis.WebSocket;",
    false,
  ],
  [
    "method call parameter",
    "({run([x]){}}).run.call(null,(function*(){new Socket(URL);yield 0;})());const Socket=globalThis.WebSocket;",
    false,
  ],
  [
    "method apply parameter",
    "({run([x]){}}).run.apply(null,[(function*(){new Socket(URL);yield 0;})()]);const Socket=globalThis.WebSocket;",
    false,
  ],
  [
    "awaited constructor argument",
    "(async()=>{new(class{constructor([x],y){}})((function*(){new Socket(URL);yield 0;})(),await ready);})();const Socket=globalThis.WebSocket;",
    true,
  ],
  [
    "non-consuming class parameter metadata",
    "new(class{constructor(x){}})((function*(){new Socket(URL);yield 0;})());const Socket=globalThis.WebSocket;",
    true,
  ],
  [
    "mandatory catch wait",
    "(async()=>{try{throw 0;}catch{await 0;}new Socket(URL);})();const Socket=globalThis.WebSocket;",
    true,
  ],
  [
    "return bypasses catch wait",
    "(async()=>{try{return;}catch{await 0;}finally{new Socket(URL);}})();const Socket=globalThis.WebSocket;",
    false,
  ],
  [
    "normal path bypasses catch wait",
    "(async()=>{try{0;}catch{await 0;}new Socket(URL);})();const Socket=globalThis.WebSocket;",
    false,
  ],
  [
    "conditional throw bypasses catch wait",
    "(async()=>{try{if(flag)throw 0;}catch{await 0;}new Socket(URL);})();const Socket=globalThis.WebSocket;",
    false,
  ],
  [
    "caught throw before finalizer",
    "(async()=>{try{throw 0;}catch{await 0;}finally{new Socket(URL);}})();const Socket=globalThis.WebSocket;",
    true,
  ],
  [
    "optional promise wrapper",
    "(async()=>{const pending=(async()=>{await ready;new Socket(URL);})();await(()=>pending)?.();const Socket=globalThis.WebSocket;})();",
    false,
  ],
  [
    "optional function promise wrapper",
    "(async()=>{const pending=(async()=>{await ready;new Socket(URL);})();await(function(){return pending;})?.();const Socket=globalThis.WebSocket;})();",
    false,
  ],
  [
    "nullish object pattern key",
    "(async()=>{const [{[await 0]:x},next]=(function*(){yield null;new Socket(URL);})();})();const Socket=globalThis.WebSocket;",
    false,
  ],
  [
    "undefined object pattern key",
    "(async()=>{const [{[await 0]:x},next]=(function*(){yield undefined;new Socket(URL);})();})();const Socket=globalThis.WebSocket;",
    false,
  ],
  [
    "nullish pattern blocks later slot wait",
    "(async()=>{const [{},x=await 0,next]=(function*(){yield null;yield undefined;new Socket(URL);})();})();const Socket=globalThis.WebSocket;",
    false,
  ],
  [
    "defined object pattern key",
    "(async()=>{const [{[await 0]:x},next]=(function*(){yield {};new Socket(URL);})();})();const Socket=globalThis.WebSocket;",
    true,
  ],
  [
    "object default selects non-null value",
    "(async()=>{const [{[await 0]:x}={},next]=(function*(){yield undefined;new Socket(URL);})();})();const Socket=globalThis.WebSocket;",
    true,
  ],
] as const;
describe("web bundle reviewed invocation and pattern phases", () => {
  it.each(invocationReviewCases)(
    "preserves %s in both consumers",
    (_name, input, present) => {
      const source = input.replaceAll(
        "URL",
        '"wss://example.test/review-invocation"',
      );
      const expected = present ? ["wss://example.test/review-invocation"] : [];
      expect(
        socketEndpoints(source).map((items) => items.map((item) => item.value)),
      ).toEqual([expected, expected]);
    },
  );
});

describe("web bundle literal consumers and iteration phases", () => {
  it.each(iterationReviewCases)(
    "preserves $name in both consumers",
    ({ source, present }) => {
      const expected = present ? ["wss://example.test/review-iteration"] : [];
      expect(
        socketEndpoints(source).map((items) => items.map((item) => item.value)),
      ).toEqual([expected, expected]);
    },
  );
});
