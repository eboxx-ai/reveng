import { semanticExactResultOperand } from "./javascriptSemanticExpressionResults.js";
import * as t from "@babel/types";

import {
  unwrapJavaScriptExpression,
  semanticDirectFunctionReturn,
} from "./javascriptAstValues.js";
import { semanticLiteralInitializerProjection } from "./javascriptSemanticLiteralProjection.js";
import {
  semanticInitializerPrecedesRead,
  type SemanticExecutionFrame,
} from "./javascriptSemanticEvaluationOrder.js";
import {
  resolveSemanticBindingState,
  semanticStableInitializer,
  type JavaScriptSemanticAnalysisState,
  type JavaScriptSemanticInitializer,
} from "./javascriptSemanticState.js";
import { createUnconditionalEvaluationProof } from "./javascriptSymbolicControlFlow.js";

/** A zero-argument literal wrapper can return a promise without allocating one. */
const directLiteralReturn = (
  node: t.Node,
  state: JavaScriptSemanticAnalysisState,
): t.Node | undefined => {
  if (
    (!t.isCallExpression(node) && !t.isOptionalCallExpression(node)) ||
    node.arguments.length !== 0
  )
    return undefined;
  let callee = unwrapJavaScriptExpression(node.callee).node;
  for (;;) {
    const result = semanticExactResultOperand(callee, state);
    if (result === undefined) break;
    callee = unwrapJavaScriptExpression(result).node;
  }
  return t.isArrowFunctionExpression(callee) || t.isFunctionExpression(callee)
    ? semanticDirectFunctionReturn(callee)
    : undefined;
};

/** Exact local promise-result identity; aliases do not prove execution order. */
export const semanticPromiseResultIdentity = (
  rawNode: t.Node,
  state: JavaScriptSemanticAnalysisState,
  onLiteralProjection?: () => void,
):
  | {
      readonly node: t.Node;
      readonly aliases: readonly {
        readonly read: t.Identifier;
        readonly initializer: JavaScriptSemanticInitializer;
      }[];
    }
  | undefined => {
  const seen = new Set<string>();
  const aliases: {
    read: t.Identifier;
    initializer: JavaScriptSemanticInitializer;
  }[] = [];
  let node = rawNode;
  for (;;) {
    node = unwrapJavaScriptExpression(node).node;
    const result =
      semanticExactResultOperand(node, state) ??
      directLiteralReturn(node, state);
    if (result !== undefined) {
      node = result;
      continue;
    }
    if (!t.isIdentifier(node)) return { node, aliases };
    const binding = resolveSemanticBindingState(state, node, node.name);
    const initializer = semanticStableInitializer(binding, state);
    if (
      binding === undefined ||
      binding.mutable ||
      initializer === undefined ||
      binding.referenceInitializers.length !== 0 ||
      seen.has(binding.bindingId)
    )
      return undefined;
    seen.add(binding.bindingId);
    const projected = semanticLiteralInitializerProjection(
      initializer,
      state,
      onLiteralProjection,
    );
    if (projected === undefined || projected.projection.length !== 0)
      return undefined;
    aliases.push({ read: node, initializer });
    node = projected.node;
  }
};

/** A returned promise can be adopted without sharing the wrapper promise's identity. */
export const semanticPromiseSettlementDependency = (
  rawNode: t.Node,
  state: JavaScriptSemanticAnalysisState,
  onLiteralProjection?: () => void,
): ReturnType<typeof semanticPromiseResultIdentity> => {
  const aliases: NonNullable<
    ReturnType<typeof semanticPromiseResultIdentity>
  >["aliases"][number][] = [];
  const seen = new Set<t.Node>();
  let current = rawNode;
  for (;;) {
    const result = semanticPromiseResultIdentity(
      current,
      state,
      onLiteralProjection,
    );
    if (result === undefined || seen.has(result.node)) return undefined;
    seen.add(result.node);
    aliases.push(...result.aliases);
    const call = unwrapJavaScriptExpression(result.node).node;
    if (
      (!t.isCallExpression(call) && !t.isOptionalCallExpression(call)) ||
      call.arguments.length !== 0
    )
      return { node: result.node, aliases };
    let callee = unwrapJavaScriptExpression(call.callee).node;
    for (;;) {
      const selected = semanticExactResultOperand(callee, state);
      if (selected === undefined) break;
      callee = unwrapJavaScriptExpression(selected).node;
    }
    if (
      (!t.isFunctionExpression(callee) &&
        !t.isArrowFunctionExpression(callee)) ||
      !callee.async
    )
      return { node: result.node, aliases };
    const returned = semanticDirectFunctionReturn(callee, { allowAsync: true });
    if (returned === undefined) return { node: result.node, aliases };
    const value = unwrapJavaScriptExpression(returned).node;
    current = t.isAwaitExpression(value) ? value.argument : value;
  }
};

const awaitedResults = new WeakMap<
  JavaScriptSemanticAnalysisState,
  {
    readonly literalEffects: JavaScriptSemanticAnalysisState["literalMemberEffects"];
    readonly iterationUnknown: boolean | undefined;
    readonly sites: WeakMap<t.Node, t.AwaitExpression[]>;
  }
>();

/** Alias identity needs initialization proof through directly owned callers. */
const promiseAliasInitializedBeforeRead = (
  initializer: JavaScriptSemanticInitializer,
  read: t.Identifier,
  state: JavaScriptSemanticAnalysisState,
  executionFrames: (node: t.Node) => readonly SemanticExecutionFrame[],
): boolean => {
  return (
    semanticInitializerPrecedesRead({
      initializer: initializer.node,
      read,
      ...(initializer.bindingNode === undefined
        ? {}
        : { bindingNode: initializer.bindingNode }),
      parents: state.parentsByNode,
      initializerContexts: executionFrames(initializer.node),
      readContexts: executionFrames(read),
    }) === true
  );
};

/** The shared activation block owns conditional producer/wait coupling. */
const promiseWaitBoundary = (
  producer: t.Node,
  wait: t.Node,
  parents: WeakMap<t.Node, t.Node>,
): t.Program | t.BlockStatement | t.SwitchCase | undefined => {
  const blocks = new Set<t.Node>();
  let current: t.Node | undefined = producer;
  while (current !== undefined && !t.isFunction(current)) {
    if (
      t.isBlockStatement(current) ||
      t.isProgram(current) ||
      t.isSwitchCase(current)
    )
      blocks.add(current);
    current = parents.get(current);
  }
  current = wait;
  while (current !== undefined && !t.isFunction(current)) {
    if (
      (t.isBlockStatement(current) ||
        t.isProgram(current) ||
        t.isSwitchCase(current)) &&
      blocks.has(current)
    )
      return current;
    current = parents.get(current);
  }
  return undefined;
};

/** Every directly invoked activation between a producer and wait must wait. */
const promiseWaitCoupledToProducer = ({
  producer,
  awaited,
  parents,
  executionFrames,
  reached,
}: {
  readonly producer: t.Node;
  readonly awaited: t.AwaitExpression;
  readonly parents: WeakMap<t.Node, t.Node>;
  readonly executionFrames: (node: t.Node) => readonly SemanticExecutionFrame[];
  readonly reached: ReturnType<typeof createUnconditionalEvaluationProof>;
}): boolean => {
  const producerFrames = executionFrames(producer);
  for (const waitFrame of executionFrames(awaited)) {
    const producerFrame = producerFrames.find(
      ({ owner }) => owner === waitFrame.owner,
    );
    if (producerFrame !== undefined) {
      const boundary = promiseWaitBoundary(
        producerFrame.point,
        waitFrame.point,
        parents,
      );
      return (
        boundary !== undefined &&
        reached(waitFrame.point, boundary, producerFrame.point)
      );
    }
    if (
      !t.isFunction(waitFrame.owner) ||
      !reached(waitFrame.point, waitFrame.owner.body)
    )
      return false;
  }
  return false;
};

/** Index waits using non-recursive direct frames, including initialized aliases. */
export const semanticAwaitedResultSites = (
  node: t.Node,
  state: JavaScriptSemanticAnalysisState,
  executionFrames: (node: t.Node) => readonly SemanticExecutionFrame[],
): readonly t.AwaitExpression[] => {
  let cached = awaitedResults.get(state);
  if (
    cached === undefined ||
    cached.literalEffects !== state.literalMemberEffects ||
    cached.iterationUnknown !== state.arrayIterationUnknown
  ) {
    const index = new WeakMap<t.Node, t.AwaitExpression[]>();
    const reached = createUnconditionalEvaluationProof(state.parentsByNode);
    for (const awaited of state.awaitSites) {
      const result = semanticPromiseSettlementDependency(
        awaited.argument,
        state,
      );
      if (result === undefined) continue;
      // Aliases retain identity only after their own initialization. Reachability
      // is relative to the block shared with the producer: entering a branch
      // can create and await a promise together without reaching either globally.
      if (result.aliases.length !== 0) {
        if (
          result.aliases.some(
            ({ initializer, read }) =>
              !promiseAliasInitializedBeforeRead(
                initializer,
                read,
                state,
                executionFrames,
              ),
          )
        )
          continue;
        if (
          !promiseWaitCoupledToProducer({
            producer: result.node,
            awaited,
            parents: state.parentsByNode,
            executionFrames,
            reached,
          })
        )
          continue;
      }
      const sites = index.get(result.node) ?? [];
      sites.push(awaited);
      index.set(result.node, sites);
    }
    cached = {
      literalEffects: state.literalMemberEffects,
      iterationUnknown: state.arrayIterationUnknown,
      sites: index,
    };
    awaitedResults.set(state, cached);
  }
  return cached.sites.get(node) ?? [];
};
