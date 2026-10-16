import { semanticExactResultOperand } from "./javascriptSemanticExpressionResults.js";
import * as t from "@babel/types";

import {
  semanticLiteralContainer,
  semanticLiteralProperty,
} from "./javascriptAstValues.js";
import { semanticPatternInitializationPrecedesRead } from "./javascriptSemanticEvaluationOrder.js";
import { semanticEffectTiming } from "./javascriptSemanticMutationInitializers.js";
import {
  semanticArrayIndex,
  semanticPropertyPathKeyMatches,
} from "./javascriptSemanticPropertyPaths.js";
import type {
  JavaScriptSemanticAnalysisState,
  JavaScriptSemanticInitializer,
} from "./javascriptSemanticState.js";

type LiteralProjectionSlot =
  | { readonly kind: "value"; readonly node: t.Node }
  | { readonly kind: "undefined" }
  | { readonly kind: "unknown" | "invalid" };

/** Share slot validity and iterator exhaustion without conflating undefined with unknown. */
export const semanticLiteralProjectionSlot = (
  node: t.Node,
  key: string | number,
  capture: t.Node,
  state: JavaScriptSemanticAnalysisState,
  options?: {
    readonly onLiteralProjection?: () => void;
    readonly ownedResultEscape?: t.Node;
  },
): LiteralProjectionSlot => {
  const exactResult = (node: t.Node) => semanticExactResultOperand(node, state);
  const container = semanticLiteralContainer(node, exactResult);
  if (container !== undefined) options?.onLiteralProjection?.();
  if (typeof key === "number" && state.arrayIterationUnknown === true)
    return { kind: "invalid" };
  if (container === undefined) return { kind: "unknown" };
  if (
    container !== undefined &&
    state.literalMemberEffects?.get(container)?.some((effect) => {
      // A proven sole pattern consumer owns this producer's result exposure;
      // it does not exempt foreign escapes, property writes or iterator effects.
      if (
        options?.ownedResultEscape !== undefined &&
        effect.kind === "escape" &&
        effect.path.length === 0 &&
        effect.node === options?.ownedResultEscape
      )
        return false;
      const [affected] = effect.path;
      const affectsSlot =
        effect.path.length === 0 ||
        (effect.kind === "write" &&
          effect.path.length === 1 &&
          affected !== undefined &&
          (semanticPropertyPathKeyMatches(affected, String(key)) ||
            (t.isArrayExpression(container) &&
              semanticArrayIndex(key) !== null &&
              affected === "length")));
      if (!affectsSlot) return false;
      const patternOrder =
        effect.node === undefined
          ? undefined
          : semanticPatternInitializationPrecedesRead(
              capture,
              effect.node,
              state.parentsByNode,
            );
      return !(
        patternOrder ??
        semanticEffectTiming(capture, effect.node, state) === "after"
      );
    })
  )
    return { kind: "invalid" };
  const value = semanticLiteralProperty(node, key, exactResult);
  if (value !== undefined) return { kind: "value", node: value };
  // Iterator exhaustion ignores inherited indexed properties; a hole within
  // the length does not. Spreads leave the actual length unknown.
  if (
    typeof key === "number" &&
    t.isArrayExpression(container) &&
    key >= container.elements.length &&
    !container.elements.some((item) => t.isSpreadElement(item))
  )
    return { kind: "undefined" };
  return { kind: "unknown" };
};

/** Resolve fresh-literal slots once, preserving capture order and iteration facts. */
export const semanticLiteralInitializerProjection = (
  initializer: JavaScriptSemanticInitializer,
  state: JavaScriptSemanticAnalysisState,
  onLiteralProjection?: () => void,
): JavaScriptSemanticInitializer | undefined => {
  let node = initializer.node;
  let projection = initializer.projection;
  while (projection.length > 0) {
    const key = projection[0];
    if (typeof key !== "string" && typeof key !== "number") return undefined;
    const selected = semanticLiteralProjectionSlot(
      node,
      key,
      initializer.bindingNode ?? initializer.node,
      state,
      onLiteralProjection === undefined ? undefined : { onLiteralProjection },
    );
    if (selected.kind === "invalid") return undefined;
    if (selected.kind !== "value") break;
    node = selected.node;
    projection = projection.slice(1);
  }
  return { ...initializer, node, projection };
};
