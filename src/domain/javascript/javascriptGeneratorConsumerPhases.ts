import * as t from "@babel/types";

import {
  readExactJavaScriptLiteral,
  semanticStaticPropertyKey,
  unwrapJavaScriptExpression,
} from "./javascriptAstValues.js";
import {
  resolveSemanticBindingState,
  type JavaScriptSemanticAnalysisState,
} from "./javascriptSemanticState.js";
import { semanticLiteralProjectionSlot } from "./javascriptSemanticLiteralProjection.js";

interface PatternWaitCache {
  readonly effects: JavaScriptSemanticAnalysisState["literalMemberEffects"];
  readonly iterationUnknown: boolean | undefined;
  readonly ownedResultEscape: t.Node | undefined;
  readonly index: number | null;
}

interface GeneratorPrefixFacts {
  readonly before: WeakMap<t.Node, number>;
  readonly yielded: readonly t.YieldExpression[];
  readonly firstPatternWait: WeakMap<t.ArrayPattern, PatternWaitCache>;
}
const prefixes = new WeakMap<t.Node, GeneratorPrefixFacts>();

/** Index only straight-line owned yields; uncertain branches do not prove a resume phase. */
const generatorPrefixes = (
  body: t.Node,
  ordered: (node: t.Node) => readonly t.Node[],
  maySuspend: (node: t.Node) => boolean,
): GeneratorPrefixFacts => {
  const cached = prefixes.get(body);
  if (cached !== undefined) return cached;
  const before = new WeakMap<t.Node, number>();
  const yielded: t.YieldExpression[] = [];
  let completed = 0;
  const pending: { node: t.Node; exit?: true }[] = [{ node: body }];
  while (pending.length > 0) {
    const entry = pending.pop();
    if (entry === undefined) continue;
    const node = unwrapJavaScriptExpression(entry.node).node;
    if (entry.exit === true) {
      if (t.isYieldExpression(node)) {
        if (node.delegate) completed = -1;
        else if (completed >= 0) {
          yielded.push(node);
          completed += 1;
        }
      }
      continue;
    }
    before.set(node, completed);
    if (t.isFunction(node)) continue;
    if (
      (t.isIfStatement(node) ||
        t.isConditionalExpression(node) ||
        t.isLogicalExpression(node) ||
        t.isLoop(node) ||
        t.isSwitchStatement(node) ||
        t.isTryStatement(node)) &&
      maySuspend(node)
    )
      completed = -1;
    if (t.isYieldExpression(node)) pending.push({ node, exit: true });
    const children = ordered(node);
    for (const child of children.toReversed()) pending.push({ node: child });
  }
  const facts = {
    before,
    yielded,
    firstPatternWait: new WeakMap<t.ArrayPattern, PatternWaitCache>(),
  };
  prefixes.set(body, facts);
  return facts;
};

type PatternValue = {
  readonly known: boolean;
  readonly node?: t.Node;
  readonly restStartIndex?: number;
  readonly ownedResultEscape?: t.Node;
};

const undefinedPatternValue = (
  value: PatternValue,
  state: JavaScriptSemanticAnalysisState,
): boolean => {
  const argument =
    value.node === undefined
      ? undefined
      : unwrapJavaScriptExpression(value.node).node;
  return (
    value.known &&
    (argument === undefined ||
      (t.isIdentifier(argument, { name: "undefined" }) &&
        resolveSemanticBindingState(state, argument, "undefined") ===
          undefined) ||
      (t.isUnaryExpression(argument, { operator: "void" }) &&
        readExactJavaScriptLiteral(argument.argument).found))
  );
};

/** Use the same mutation and iterator proof as ordinary literal projections. */
const patternPropertyValue = (
  value: PatternValue,
  key: string | number,
  state: JavaScriptSemanticAnalysisState,
  capture: t.Node,
): PatternValue => {
  if (!value.known || value.node === undefined) return { known: false };
  const node = unwrapJavaScriptExpression(value.node).node;
  if (value.restStartIndex !== undefined && typeof key !== "number")
    return { known: false };
  const selected = semanticLiteralProjectionSlot(
    node,
    typeof key === "number" ? key + (value.restStartIndex ?? 0) : key,
    capture,
    state,
    value.ownedResultEscape === undefined
      ? undefined
      : { ownedResultEscape: value.ownedResultEscape },
  );
  if (selected.kind === "value")
    return {
      known: true,
      node: selected.node,
      ...(value.ownedResultEscape === undefined
        ? {}
        : { ownedResultEscape: value.ownedResultEscape }),
    };
  if (selected.kind === "undefined") return { known: true };
  return { known: false };
};

/** A rest copy owns a fresh suffix array; retain indices without synthesizing AST. */
const patternArrayRest = (
  value: PatternValue,
  index: number,
  state: JavaScriptSemanticAnalysisState,
): PatternValue => {
  const node =
    value.node === undefined
      ? undefined
      : unwrapJavaScriptExpression(value.node).node;
  return value.known &&
    t.isArrayExpression(node) &&
    state.arrayIterationUnknown !== true &&
    !node.elements.some((item) => t.isSpreadElement(item))
    ? {
        known: true,
        node,
        restStartIndex: (value.restStartIndex ?? 0) + index,
        ...(value.ownedResultEscape === undefined
          ? {}
          : { ownedResultEscape: value.ownedResultEscape }),
      }
    : { known: false };
};

type PatternCompletion = "completed" | "suspended" | "blocked";

/** Work completed inside a consumed slot precedes the next generator resume. */
const patternCompletedSuspension = (
  pattern: t.Node,
  value: PatternValue,
  state: JavaScriptSemanticAnalysisState,
  suspended: (node: t.Node) => boolean,
  depth = 0,
  target?: t.Node,
  targetPath?: ReadonlySet<t.Node>,
): PatternCompletion => {
  if (depth >= 128) return "blocked";
  if (pattern === target) return "completed";
  if (t.isAssignmentPattern(pattern)) {
    const selectsDefault = undefinedPatternValue(value, state);
    return selectsDefault && suspended(pattern.right)
      ? "suspended"
      : patternCompletedSuspension(
          pattern.left,
          selectsDefault ? { known: true, node: pattern.right } : value,
          state,
          suspended,
          depth + 1,
          target,
          targetPath,
        );
  }
  if (t.isObjectPattern(pattern)) {
    // RequireObjectCoercible precedes property keys and rest operations.
    // A definite failure also blocks waits in later consumed slots.
    if (
      undefinedPatternValue(value, state) ||
      (value.known &&
        value.node !== undefined &&
        t.isNullLiteral(unwrapJavaScriptExpression(value.node).node))
    )
      return "blocked";
    for (const property of pattern.properties) {
      if (t.isRestElement(property)) continue;
      if (property.computed && suspended(property.key)) return "suspended";
      const key = semanticStaticPropertyKey(property.key, property.computed);
      const completion = patternCompletedSuspension(
        property.value,
        key === null
          ? { known: false }
          : patternPropertyValue(value, key, state, pattern),
        state,
        suspended,
        depth + 1,
        target,
        targetPath,
      );
      if (completion !== "completed") return completion;
      if (targetPath?.has(property)) return "completed";
    }
  }
  if (t.isArrayPattern(pattern))
    for (const [index, element] of pattern.elements.entries()) {
      if (element === null) continue;
      const completion = patternCompletedSuspension(
        t.isRestElement(element) ? element.argument : element,
        t.isRestElement(element)
          ? patternArrayRest(value, index, state)
          : patternPropertyValue(value, index, state, pattern),
        state,
        suspended,
        depth + 1,
        target,
        targetPath,
      );
      if (completion !== "completed") return completion;
      if (targetPath?.has(element)) return "completed";
    }
  return "completed";
};

/** Selected defaults and keys before a particular destructuring write share slot semantics. */
export const semanticPatternSuspendsBeforeTarget = (
  pattern: t.Node,
  value: t.Node,
  target: t.Node,
  state: JavaScriptSemanticAnalysisState,
  completedSuspension: (node: t.Node) => boolean,
): boolean => {
  const path = new Set<t.Node>();
  let current: t.Node | undefined = target;
  while (current !== undefined) {
    path.add(current);
    if (current === pattern)
      return (
        patternCompletedSuspension(
          pattern,
          { known: true, node: value },
          state,
          completedSuspension,
          0,
          target,
          path,
        ) === "suspended"
      );
    current = state.parentsByNode.get(current);
  }
  return false;
};

/** Only completed work in an earlier consumed slot can delay the next iterator step. */
export const semanticPatternSuspendsBeforeGeneratorRead = ({
  read,
  body,
  pattern,
  state,
  ordered,
  maySuspend,
  completedSuspension,
  ownedResultEscape,
}: {
  readonly read: t.Node;
  readonly body: t.Node;
  readonly pattern: t.ArrayPattern;
  readonly state: JavaScriptSemanticAnalysisState;
  readonly ordered: (node: t.Node) => readonly t.Node[];
  readonly maySuspend: (node: t.Node) => boolean;
  readonly completedSuspension: (node: t.Node) => boolean;
  readonly ownedResultEscape?: t.Node;
}): boolean => {
  const facts = generatorPrefixes(body, ordered, maySuspend);
  const count = facts.before.get(unwrapJavaScriptExpression(read).node);
  if (count === undefined || count < 0) return false;
  const cached = facts.firstPatternWait.get(pattern);
  if (
    cached !== undefined &&
    cached.effects === state.literalMemberEffects &&
    cached.iterationUnknown === state.arrayIterationUnknown &&
    cached.ownedResultEscape === ownedResultEscape
  )
    return cached.index !== null && cached.index < count;
  const cache = (index: number | null): void => {
    facts.firstPatternWait.set(pattern, {
      effects: state.literalMemberEffects,
      iterationUnknown: state.arrayIterationUnknown,
      ownedResultEscape,
      index,
    });
  };
  for (let index = 0; index < pattern.elements.length; index += 1) {
    const element = pattern.elements[index];
    if (t.isRestElement(element)) break;
    if (element == null) continue;
    const yielded = facts.yielded[index];
    if (yielded === undefined) break;
    const completion = patternCompletedSuspension(
      element,
      {
        known: true,
        ...(yielded.argument == null ? {} : { node: yielded.argument }),
        ...(ownedResultEscape === undefined ? {} : { ownedResultEscape }),
      },
      state,
      completedSuspension,
    );
    if (completion === "blocked") break;
    if (completion === "suspended") {
      cache(index);
      return index < count;
    }
  }
  cache(null);
  return false;
};
