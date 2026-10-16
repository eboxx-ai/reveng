import { semanticExactResultOperand } from "./javascriptSemanticExpressionResults.js";
import * as t from "@babel/types";

import {
  javaScriptExactResultOperand,
  semanticStaticPropertyKey,
  unwrapJavaScriptExpression,
} from "./javascriptAstValues.js";
import {
  collectJavaScriptIdentityWritesSteps,
  electronMemberPath,
} from "./javascriptElectronMemberWrites.js";
import { createSemanticModuleInterop } from "./javascriptModuleInterop.js";
import {
  isUnshadowedGlobal,
  resolveSemanticBindingState,
  semanticStableInitializer,
  type JavaScriptSemanticAnalysisState,
} from "./javascriptSemanticState.js";
import { isImportMetaUrl } from "./javascriptStaticAnalysisHelpers.js";
import {
  semanticMutationInitializers,
  semanticTopLevelEffectFollowsCapture,
} from "./javascriptSemanticMutationInitializers.js";
import { semanticRequireOrigin } from "./javascriptSemanticRequireOrigin.js";
import { semanticPropertyPathKeyMatches } from "./javascriptSemanticPropertyPaths.js";

const GLOBAL_OBJECT_NAMES = ["globalThis", "global", "window", "self"];

/** The CommonJS ws constructor's repeated self members select the same export. */
export const semanticRequiredWebSocketProjection = (
  path: readonly string[],
): readonly string[] | undefined => {
  const canonical = canonicalAmbientPath(["commonjs-ws", ...path]);
  return canonical.length === 1
    ? path.length === 0
      ? []
      : ["WebSocket"]
    : undefined;
};

const globalObjectName = (
  node: t.Node,
  state: JavaScriptSemanticAnalysisState,
): string | undefined =>
  GLOBAL_OBJECT_NAMES.find((name) => isUnshadowedGlobal(node, state, name));

/** Global self references retain object identity, rather than adding a property. */
const canonicalAmbientPath = (
  path: readonly (string | null)[],
  onGlobalSelf?: (name: string) => void,
): readonly (string | null)[] => {
  // The CommonJS ws constructor is its own WebSocket member. Resolve the
  // written receiver first; the collector then appends the actual replaced key.
  if (path[0] === "commonjs-ws") {
    let member = 1;
    while (path[member] === "WebSocket") member += 1;
    return ["commonjs-ws", ...path.slice(member)];
  }
  if (path[0] !== "global") return path;
  let firstProperty = 1;
  while (GLOBAL_OBJECT_NAMES.includes(path[firstProperty] ?? "")) {
    onGlobalSelf?.(path[firstProperty] as string);
    firstProperty += 1;
  }
  return ["global", ...path.slice(firstProperty)];
};

type AmbientPath = readonly (string | null)[];

/** Undefined means a cyclic or conflicting projection can select any depth. */
type AmbientProjection = AmbientPath | undefined;

/**
 * Follow local object identities without equating shallow copies with their
 * sources. Write lookup retains every visible initializer: reassigning an alias
 * later cannot erase a possible earlier mutation. Intrinsic reads stay strict.
 */
const createAmbientPathResolver = (
  state: JavaScriptSemanticAnalysisState,
  possibleWrites: boolean,
) => {
  const cached = new WeakMap<t.Node, readonly AmbientPath[]>();
  return (node: t.Node, capture?: t.Node): readonly AmbientPath[] => {
    const prior = possibleWrites ? undefined : cached.get(node);
    if (prior !== undefined) return prior;
    const result = new Map<string, AmbientPath>();
    // The caller's write site selects initializers for the written target.
    // Reads reached through an initializer occur at their own position.
    const pending: {
      node: t.Node;
      suffix: AmbientProjection;
      readsAtSelf?: true;
    }[] = [{ node, suffix: [] }];
    // Join projections at their producing expression, rather than enumerating
    // alias histories. Each key can only widen to a wildcard, and conflicting
    // depths widen to unknown, so diamonds and cycles have finite state.
    const expanded = new WeakMap<t.Node, AmbientProjection>();
    const retain = (path: AmbientPath) => {
      let canonical = canonicalAmbientPath(path);
      for (;;) {
        result.set(JSON.stringify(canonical), canonical);
        // An unknown key may select a known self reference as well as a
        // distinct property. Retain both possible object identities for writes.
        if (
          !possibleWrites ||
          (canonical[0] !== "global" && canonical[0] !== "commonjs-ws") ||
          canonical[1] !== null
        )
          break;
        canonical = canonicalAmbientPath([canonical[0], ...canonical.slice(2)]);
      }
    };
    while (pending.length > 0) {
      const current = pending.pop();
      if (current === undefined) break;
      const { root, members } = electronMemberPath(current.node);
      let suffix: AmbientProjection =
        current.suffix === undefined
          ? undefined
          : [...members, ...current.suffix];
      if (expanded.has(root)) {
        const previous = expanded.get(root);
        if (previous === undefined) continue;
        if (suffix !== undefined && previous.length === suffix.length) {
          const joined: AmbientPath = previous.map((key, index) =>
            key === suffix?.[index] ? key : null,
          );
          if (joined.every((key, index) => key === previous[index])) continue;
          suffix = joined;
        } else suffix = undefined;
        if (!possibleWrites) {
          cached.set(node, []);
          return [];
        }
      }
      expanded.set(root, suffix);
      // A widened projection is a possible write, never proof of an intrinsic.
      if (suffix === undefined && !possibleWrites) continue;
      const continueWith = (node: t.Node, path: AmbientProjection = suffix) =>
        pending.push({
          node,
          suffix: path,
          ...(current.readsAtSelf && { readsAtSelf: true }),
        });
      const exactResult = possibleWrites
        ? javaScriptExactResultOperand(root, () => true)
        : semanticExactResultOperand(root, state);
      if (exactResult !== undefined) {
        continueWith(exactResult);
        continue;
      }
      if (
        t.isMetaProperty(root) &&
        root.meta.name === "import" &&
        root.property.name === "meta"
      ) {
        retain(["import-meta", ...(suffix ?? [])]);
        continue;
      }
      if (t.isIdentifier(root)) {
        // The wrapper module object is distinct from globalThis.module. Keep
        // its identity through the same alias/projection owner used for writes.
        if (isUnshadowedGlobal(root, state, "module")) {
          retain(["commonjs-module", ...(suffix ?? [])]);
          continue;
        }
        if (globalObjectName(root, state) !== undefined) {
          retain(["global", ...(suffix ?? [])]);
          continue;
        }
        if (isUnshadowedGlobal(root, state, root.name)) {
          retain(["global", root.name, ...(suffix ?? [])]);
          continue;
        }
        const binding = resolveSemanticBindingState(state, root, root.name);
        if (binding === undefined) continue;
        const readAt = current.readsAtSelf ? root : capture;
        const selected =
          possibleWrites && readAt !== undefined
            ? semanticMutationInitializers(binding, readAt, state.parentsByNode)
            : undefined;
        for (const origin of selected?.directOrigins ?? binding.directOrigins)
          if (origin.resolutionMode === "require" && origin.specifier === "ws")
            retain(["commonjs-ws", ...origin.importedPath, ...(suffix ?? [])]);
        const stable = semanticStableInitializer(binding, state);
        const initializers = possibleWrites
          ? readAt === undefined
            ? binding.initializers
            : (selected?.initializers ?? [])
          : stable === undefined
            ? []
            : [stable];
        for (const initializer of initializers)
          pending.push({
            node: initializer.node,
            readsAtSelf: true,
            suffix:
              suffix === undefined
                ? undefined
                : [
                    ...initializer.projection.map((key) =>
                      key === null ? null : String(key),
                    ),
                    ...suffix,
                  ],
          });
        continue;
      }
      if (possibleWrites && t.isConditionalExpression(root)) {
        continueWith(root.consequent);
        continueWith(root.alternate);
        continue;
      }
      if (possibleWrites && t.isLogicalExpression(root)) {
        continueWith(root.left);
        continueWith(root.right);
        continue;
      }
      const required = semanticRequireOrigin(root, state)?.origin;
      if (required?.specifier === "ws") {
        retain(["commonjs-ws", ...required.importedPath, ...(suffix ?? [])]);
        continue;
      }
      const key = suffix?.[0];
      if (suffix !== undefined && key === undefined) continue;
      if (t.isObjectExpression(root)) {
        if (possibleWrites) {
          for (const property of root.properties) {
            if (t.isSpreadElement(property)) continueWith(property.argument);
            else if (
              t.isObjectProperty(property) &&
              t.isExpression(property.value)
            ) {
              const ownKey = semanticStaticPropertyKey(
                property.key,
                property.computed,
              );
              if (
                suffix === undefined ||
                key === null ||
                ownKey === null ||
                ownKey === key
              )
                continueWith(property.value, suffix?.slice(1));
            }
          }
        } else if (
          suffix !== undefined &&
          key !== null &&
          root.properties.every(
            (property) =>
              t.isObjectProperty(property) &&
              semanticStaticPropertyKey(property.key, property.computed) !==
                null,
          )
        ) {
          const property = root.properties.findLast(
            (property) =>
              t.isObjectProperty(property) &&
              semanticStaticPropertyKey(property.key, property.computed) ===
                key,
          );
          if (t.isObjectProperty(property) && t.isExpression(property.value))
            continueWith(property.value, suffix.slice(1));
        }
      } else if (t.isArrayExpression(root)) {
        if (suffix === undefined) {
          for (const element of root.elements)
            if (t.isSpreadElement(element)) continueWith(element.argument);
            else if (t.isExpression(element)) continueWith(element);
        } else if (!root.elements.some(t.isSpreadElement)) {
          const index = Number(key);
          if (key === null && possibleWrites) {
            for (const element of root.elements)
              if (t.isExpression(element))
                continueWith(element, suffix.slice(1));
          } else if (
            key !== null &&
            Number.isInteger(index) &&
            index >= 0 &&
            String(index) === key
          ) {
            const element = root.elements[index];
            if (t.isExpression(element)) continueWith(element, suffix.slice(1));
          }
        }
      }
    }
    const paths = [...result.values()];
    if (!possibleWrites) cached.set(node, paths);
    return paths;
  };
};

/**
 * Index source-local writes through ambient identities and stable aliases.
 * The shared invocation owner resolves intrinsic aliases, bind/call/apply and
 * literal argument spreads. Runtime reachability and arbitrary call effects
 * remain unevaluated; a visible possible write is sufficient.
 */
export function* indexJavaScriptAmbientWritesSteps(
  program: t.Program,
  state: JavaScriptSemanticAnalysisState,
): Generator<void> {
  const ambientReads = createAmbientPathResolver(state, false);
  const ambientWrites = createAmbientPathResolver(state, true);
  const interop = createSemanticModuleInterop(state, {
    intrinsicPath: (node) => {
      const [path] = ambientReads(node);
      return path?.[0] === "global" && path.every((key) => key !== null)
        ? ["intrinsic", ...(path.slice(1) as readonly string[])]
        : undefined;
    },
  });
  yield* collectJavaScriptIdentityWritesSteps(
    program,
    (root, kind, writeSite) => {
      if (kind === "opaque-call") return [];
      // Reassigning a local alias changes the binding, not the referenced object.
      if (kind === "binding")
        return t.isIdentifier(root) &&
          isUnshadowedGlobal(root, state, root.name)
          ? [["global", root.name]]
          : [];
      return ambientWrites(root, writeSite);
    },
    interop.intrinsicInvocation,
    interop.staticString,
    interop.isFreshObject,
    (node, path) => {
      state.ambientWrites.retain(path);
      state.ambientWriteEffects.push({ path, node });
    },
  );
}

/**
 * Recognize an ambient property path, optionally through a global object, without a visible
 * source-local overwrite. This is a syntax-local identity fact, not proof that
 * the runtime's globals have never been patched by other code.
 */
export const isUnmodifiedGlobalReference = (
  callee: t.Node,
  state: JavaScriptSemanticAnalysisState,
  name: string | readonly [string, ...string[]],
  projection: readonly string[] = [],
): boolean => {
  const path: readonly [string, ...string[]] =
    typeof name === "string" ? [name] : name;
  if (state.ambientWrites.covers(["global", ...path])) return false;
  const { root, members } = electronMemberPath(callee);
  const selected = [...members, ...projection];
  const matches = (expected: readonly string[], actual = selected) =>
    actual.length === expected.length &&
    actual.every((key, index) => key === expected[index]);
  if (isUnshadowedGlobal(root, state, path[0]) && matches(path.slice(1)))
    return true;
  const namespace = globalObjectName(root, state);
  let selfReferencesUnmodified = true;
  const canonical = canonicalAmbientPath(["global", ...selected], (name) => {
    if (state.ambientWrites.covers(["global", name]))
      selfReferencesUnmodified = false;
  });
  return (
    namespace !== undefined &&
    selfReferencesUnmodified &&
    matches(path, canonical.slice(1)) &&
    !state.ambientWrites.covers(["global", namespace])
  );
};

/** Keep selected CommonJS exports separate from earlier captured constructors. */
export const isUnmodifiedRequiredWebSocketReference = (
  capture: t.Node,
  state: JavaScriptSemanticAnalysisState,
  projection: readonly string[],
): boolean => {
  const selected = ["commonjs-ws", ...projection];
  if (!state.ambientWrites.covers(selected)) return true;
  return !state.ambientWriteEffects.some(
    ({ path, node }) =>
      path.length <= selected.length &&
      path.every((key, index) =>
        semanticPropertyPathKeyMatches(key, selected[index] ?? ""),
      ) &&
      !semanticTopLevelEffectFollowsCapture(capture, node, state.parentsByNode),
  );
};

/** A module URL base is known only while its property has no visible write. */
export const isUnmodifiedImportMetaUrl = (
  node: t.Node | undefined,
  state: JavaScriptSemanticAnalysisState,
): boolean =>
  isImportMetaUrl(node) && !state.ambientWrites.covers(["import-meta", "url"]);
