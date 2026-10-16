import * as t from "@babel/types";
import { syntaxEvaluationCannotThrow } from "./javascriptSymbolicControlFlow.js";

import {
  javaScriptExactResultOperand,
  unwrapJavaScriptExpression,
} from "./javascriptAstValues.js";
import {
  semanticInitializerPrecedesRead,
  type SemanticExecutionFrame,
} from "./javascriptSemanticEvaluationOrder.js";
import {
  resolveSemanticBindingState,
  type JavaScriptSemanticAnalysisState,
  type JavaScriptSemanticBindingState,
} from "./javascriptSemanticState.js";

/** Compare a local binding event in its own lexical activation, without guessing callers. */
const lexicalFrame = (
  node: t.Node,
  state: JavaScriptSemanticAnalysisState,
): SemanticExecutionFrame => {
  let current = node;
  for (;;) {
    const parent = state.parentsByNode.get(current);
    if (parent === undefined || t.isFunction(parent) || t.isProgram(parent))
      return { owner: parent ?? current, point: node };
    current = parent;
  }
};

/** Local value reads and writable results share the same initialization event proof. */
const bindingInitializedBeforeRead = (
  binding: JavaScriptSemanticBindingState,
  node: t.Node,
  state: JavaScriptSemanticAnalysisState,
  executionFrames?: (node: t.Node) => readonly SemanticExecutionFrame[],
): boolean => {
  if (binding.runtimeImport) return false;
  if (binding.declarationKinds.has("var")) return true;
  if (
    binding.definitionNodes.some((definition) => {
      const owner = state.parentsByNode.get(definition);
      return t.isFunctionDeclaration(owner) && owner.id === definition;
    })
  )
    return true;
  if (
    ![...binding.declarationKinds].some((kind) =>
      ["let", "const", "using", "await using"].includes(kind),
    )
  )
    return false;
  return binding.definitionNodes.some((bindingNode) => {
    let declaration: t.Node | undefined = bindingNode;
    while (
      declaration !== undefined &&
      !t.isVariableDeclarator(declaration) &&
      !t.isFunction(declaration)
    )
      declaration = state.parentsByNode.get(declaration);
    return (
      t.isVariableDeclarator(declaration) &&
      semanticInitializerPrecedesRead({
        initializer: declaration,
        read: node,
        bindingNode,
        parents: state.parentsByNode,
        initializerContexts: executionFrames?.(declaration) ?? [
          lexicalFrame(declaration, state),
        ],
        readContexts: executionFrames?.(node) ?? [lexicalFrame(node, state)],
      }) === true
    );
  });
};

/** Parameters, private names and arbitrary setters still need different completion proofs. */
const assignmentCanComplete = (
  node: t.AssignmentExpression,
  state: JavaScriptSemanticAnalysisState,
  executionFrames?: (node: t.Node) => readonly SemanticExecutionFrame[],
): boolean => {
  const target = unwrapJavaScriptExpression(node.left).node;
  if (!t.isIdentifier(target)) return false;
  const binding = resolveSemanticBindingState(state, target, target.name);
  return (
    binding !== undefined &&
    ![...binding.declarationKinds].some(
      (kind) => kind === "const" || kind === "using" || kind === "await using",
    ) &&
    bindingInitializedBeforeRead(binding, node, state, executionFrames)
  );
};

const prefixCanComplete = (
  rawNode: t.Node,
  state: JavaScriptSemanticAnalysisState,
  executionFrames?: (node: t.Node) => readonly SemanticExecutionFrame[],
): boolean => {
  const node = unwrapJavaScriptExpression(rawNode).node;
  if (syntaxEvaluationCannotThrow(node)) return true;
  if (t.isIdentifier(node)) {
    const binding = resolveSemanticBindingState(state, node, node.name);
    return (
      binding !== undefined &&
      bindingInitializedBeforeRead(binding, node, state, executionFrames)
    );
  }
  return (
    t.isAssignmentExpression(node) &&
    node.operator === "=" &&
    assignmentCanComplete(node, state, executionFrames) &&
    prefixCanComplete(node.right, state, executionFrames)
  );
};

/** Value identity follows assignment RHS only after its target write can complete. */
export const semanticExactResultOperand = (
  node: t.Node,
  state: JavaScriptSemanticAnalysisState,
  executionFrames?: (node: t.Node) => readonly SemanticExecutionFrame[],
): t.Node | undefined => {
  const selected = unwrapJavaScriptExpression(node).node;
  if (
    t.isSequenceExpression(selected) &&
    !selected.expressions
      .slice(0, -1)
      .every((prefix) => prefixCanComplete(prefix, state, executionFrames))
  )
    return undefined;
  return javaScriptExactResultOperand(node, (assignment) =>
    assignmentCanComplete(assignment, state, executionFrames),
  );
};
