import * as t from "@babel/types";

import type { JavaScriptModuleOrigin } from "./javascriptSemanticIr.js";
import { semanticMemberChain } from "./javascriptSemanticRequireOrigin.js";
import { unwrapJavaScriptExpression } from "./javascriptAstValues.js";
import { stringValue } from "./javascriptStaticAnalysisHelpers.js";
import type { JavaScriptSemanticAnalysisState } from "./javascriptSemanticState.js";
import { semanticPromiseSettlementDependency } from "./javascriptSemanticPromiseIdentity.js";
import { webSocketInitializerDominatesRead } from "./javascriptWebSocketExecution.js";

/** Recover an exact export of a fulfilled literal import, never its promise. */
export const semanticAwaitedImportOrigin = (
  node: t.Node,
  state: JavaScriptSemanticAnalysisState,
  onLiteralProjection?: () => void,
): JavaScriptModuleOrigin | undefined => {
  const chain = semanticMemberChain(node);
  if (chain === undefined || !t.isAwaitExpression(chain.root)) return undefined;
  const result = semanticPromiseSettlementDependency(
    chain.root.argument,
    state,
    onLiteralProjection,
  );
  if (
    result === undefined ||
    result.aliases.some(
      ({ read, initializer }) =>
        !webSocketInitializerDominatesRead(
          initializer.node,
          read,
          state,
          initializer.bindingNode,
        ),
    )
  )
    return undefined;
  const imported = unwrapJavaScriptExpression(result.node).node;
  const source = t.isImportExpression(imported)
    ? imported.source
    : t.isCallExpression(imported) && t.isImport(imported.callee)
      ? imported.arguments[0]
      : undefined;
  const specifier = stringValue(source);
  return specifier === undefined
    ? undefined
    : { specifier, importedPath: chain.members, resolutionMode: "import" };
};
