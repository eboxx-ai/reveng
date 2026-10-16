import * as t from "@babel/types";
import {
  semanticPatternSuspendsBeforeGeneratorRead,
  semanticPatternSuspendsBeforeTarget,
} from "./javascriptGeneratorConsumerPhases.js";

import {
  unwrapJavaScriptExpression,
  semanticStaticPropertyName,
  readExactJavaScriptLiteral,
  semanticFinalObjectMember,
  semanticFinalClassMember,
  semanticStaticPropertyKey,
  javaScriptClassField,
  semanticDirectFunctionReturn,
  semanticValueIsRead,
  semanticValueWriteSite,
  javaScriptExactResultOperand,
  runtimeFunctionParameters,
} from "./javascriptAstValues.js";
import {
  javaScriptOptionalOperandsMayBeSkipped,
  semanticInitializerPrecedesRead,
  type SemanticExecutionFrame,
} from "./javascriptSemanticEvaluationOrder.js";
import type { JavaScriptSemanticAnalysisState } from "./javascriptSemanticState.js";
import { semanticAwaitedResultSites } from "./javascriptSemanticPromiseIdentity.js";
import {
  syntaxMayExitByJump,
  syntaxUnconditionalOperands,
  syntaxEvaluationOperands,
  syntaxEvaluationCannotThrow,
  syntaxMayCompleteNormally,
  syntaxAlwaysThrows,
} from "./javascriptSymbolicControlFlow.js";
import { childNodes } from "./javascriptSemanticTraversal.js";

/** A selected getter read owns its exact returned value, separately from its body. */
const webSocketReturnedGetter = (
  value: t.Node,
  state: JavaScriptSemanticAnalysisState,
): t.ObjectMethod | t.ClassMethod | undefined => {
  const statement = state.parentsByNode.get(value);
  if (!t.isReturnStatement(statement) || statement.argument !== value)
    return undefined;
  const block = state.parentsByNode.get(statement);
  const owner =
    block === undefined ? undefined : state.parentsByNode.get(block);
  return (t.isObjectMethod(owner) || t.isClassMethod(owner)) &&
    owner.kind === "get" &&
    semanticDirectFunctionReturn(owner) === value
    ? owner
    : undefined;
};

/** Outward syntax wrappers preserve the expression's runtime identity. */
const webSocketOuterExpression = (
  node: t.Node,
  state: JavaScriptSemanticAnalysisState,
  stopAtPatternConsumer = false,
): t.Node => {
  let current = node;
  let identity = node;
  for (;;) {
    const parent = state.parentsByNode.get(current);
    if (
      stopAtPatternConsumer &&
      t.isAssignmentExpression(parent) &&
      parent.right === current &&
      (t.isArrayPattern(parent.left) || t.isObjectPattern(parent.left))
    )
      return current;
    if (
      parent !== undefined &&
      // Invocation order is conditional on reaching the body, not on proving
      // that every prefix or target write can finish. A reached call retains
      // this frame independently of the stricter completed-value proof.
      javaScriptExactResultOperand(parent, () => true) === current
    ) {
      current = parent;
      identity = parent;
      continue;
    }
    if (
      parent === undefined ||
      unwrapJavaScriptExpression(parent).node !== identity
    ) {
      const getter = webSocketReturnedGetter(current, state);
      const selection =
        getter === undefined
          ? undefined
          : webSocketFreshMethodSelection(getter, getter, state);
      if (selection === undefined) return current;
      current = selection;
      identity = selection;
      continue;
    }
    current = parent;
  }
};

/** A directly selected method/data function on a fresh literal owns its call. */
const webSocketFreshMethodSelection = (
  node: t.Function | t.ClassExpression,
  value: t.Node,
  state: JavaScriptSemanticAnalysisState,
): t.MemberExpression | t.OptionalMemberExpression | undefined => {
  const parent = state.parentsByNode.get(value);
  const property =
    (t.isObjectMethod(node) || t.isClassMethod(node)) &&
    (node.kind === "method" || node.kind === "get" || node.kind === "set")
      ? node
      : (t.isObjectProperty(parent) || javaScriptClassField(parent)) &&
          parent.value === value
        ? parent
        : undefined;
  if (property === undefined) return undefined;
  const container = state.parentsByNode.get(property);
  const literal = t.isClassBody(container)
    ? state.parentsByNode.get(container)
    : container;
  if (!t.isObjectExpression(literal) && !t.isClassExpression(literal))
    return undefined;
  let object = webSocketOuterExpression(literal, state);
  const isStatic =
    !t.isClassMethod(property) && !javaScriptClassField(property)
      ? true
      : property.static;
  if (!isStatic) {
    const construction = state.parentsByNode.get(object);
    if (!t.isNewExpression(construction) || construction.callee !== object)
      return undefined;
    object = webSocketOuterExpression(construction, state);
  }
  const member = state.parentsByNode.get(object);
  if (
    (!t.isMemberExpression(member) && !t.isOptionalMemberExpression(member)) ||
    member.object !== object
  )
    return undefined;
  const key = semanticStaticPropertyKey(member.property, member.computed);
  return key !== null &&
    (t.isObjectExpression(literal)
      ? semanticFinalObjectMember(
          literal,
          key,
          t.isObjectMethod(property) && property.kind === "set" ? "set" : "get",
        )
      : semanticFinalClassMember(
          literal,
          key,
          isStatic,
          t.isClassMethod(property) && property.kind === "set" ? "set" : "get",
        )) === property
    ? member
    : undefined;
};

/** Binding a literal defers it only until that bound result is invoked. */
const webSocketImmediateInvocation = (
  node: t.Function | t.ClassExpression,
  state: JavaScriptSemanticAnalysisState,
):
  | t.CallExpression
  | t.OptionalCallExpression
  | t.NewExpression
  | t.TaggedTemplateExpression
  | t.Decorator
  | t.MemberExpression
  | t.OptionalMemberExpression
  | undefined => {
  const value = webSocketOuterExpression(node, state);
  const selection = webSocketFreshMethodSelection(node, value, state);
  // Reading an accessor invokes its getter before any returned value is called.
  if (
    selection !== undefined &&
    (t.isObjectMethod(node) || t.isClassMethod(node)) &&
    node.kind === "get"
  )
    return semanticValueIsRead(selection, state.parentsByNode)
      ? selection
      : undefined;
  if (
    selection !== undefined &&
    (t.isObjectMethod(node) || t.isClassMethod(node)) &&
    node.kind === "set"
  )
    return semanticValueWriteSite(selection, state.parentsByNode) !== undefined
      ? selection
      : undefined;
  let callee =
    selection === undefined
      ? value
      : webSocketOuterExpression(selection, state);
  for (;;) {
    let invocation = state.parentsByNode.get(callee);
    let binds = false;
    if (
      (t.isMemberExpression(invocation) ||
        t.isOptionalMemberExpression(invocation)) &&
      invocation.object === callee
    ) {
      const member = semanticStaticPropertyName(
        invocation.property,
        invocation.computed,
      );
      if (member !== "call" && member !== "apply" && member !== "bind")
        return undefined;
      binds = member === "bind";
      callee = webSocketOuterExpression(invocation, state);
      invocation = state.parentsByNode.get(callee);
    }
    if (t.isDecorator(invocation)) {
      if (invocation.expression !== callee) return undefined;
    } else if (t.isTaggedTemplateExpression(invocation)) {
      if (invocation.tag !== callee) return undefined;
    } else if (
      (!t.isCallExpression(invocation) &&
        !t.isOptionalCallExpression(invocation) &&
        !t.isNewExpression(invocation)) ||
      invocation.callee !== callee
    )
      return undefined;
    if (!binds || t.isNewExpression(invocation)) return invocation;
    callee = webSocketOuterExpression(invocation, state);
  }
};

type WebSocketSuspension =
  | t.AwaitExpression
  | t.YieldExpression
  | t.ForOfStatement
  | t.BlockStatement;

const loopJumpFacts = new WeakMap<t.Node, boolean>();
/** An abrupt loop path cannot prove normal body completion before its test/update. */
const webSocketBodyMayJump = (body: t.Node): boolean => {
  const known = loopJumpFacts.get(body);
  if (known !== undefined) return known;
  const mayJump = syntaxMayExitByJump(body);
  loopJumpFacts.set(body, mayJump);
  return mayJump;
};

const scopeExitSuspensions = new WeakMap<
  t.BlockStatement,
  t.AwaitExpression | t.BlockStatement | null
>();
/** A wait precedes every scope exit only if no earlier throw/jump can bypass it. */
const webSocketEveryExitSuspension = (
  block: t.BlockStatement,
): t.AwaitExpression | t.BlockStatement | undefined => {
  const known = scopeExitSuspensions.get(block);
  if (known !== undefined) return known ?? undefined;
  const pending: t.Node[] = [block];
  while (pending.length > 0) {
    const next = pending.pop();
    if (next === undefined) break;
    const node = unwrapJavaScriptExpression(next).node;
    if (
      t.isAwaitExpression(node) &&
      readExactJavaScriptLiteral(node.argument).found
    ) {
      scopeExitSuspensions.set(block, node);
      return node;
    }
    if (syntaxEvaluationCannotThrow(node)) continue;
    // A successfully acquired null async resource still schedules a disposal
    // await on every exit, including throw/return/break. The declaration itself
    // does not suspend, and a possibly throwing initializer cannot prove this.
    if (
      t.isVariableDeclaration(node) &&
      node.kind === "await using" &&
      t.isIdentifier(node.declarations[0]?.id) &&
      t.isNullLiteral(node.declarations[0]?.init)
    ) {
      scopeExitSuspensions.set(block, block);
      return block;
    }
    if (t.isExpressionStatement(node)) pending.push(node.expression);
    else if (t.isThrowStatement(node) || t.isReturnStatement(node)) {
      // Abrupt completion discards every later statement, but evaluates its
      // argument before entering a finalizer.
      pending.length = 0;
      if (node.argument != null) pending.push(node.argument);
    } else if (t.isBlockStatement(node))
      pending.push(...node.body.toReversed());
    else if (t.isSequenceExpression(node))
      pending.push(...node.expressions.toReversed());
    else if (
      t.isVariableDeclaration(node) &&
      (node.kind === "var" || node.kind === "let" || node.kind === "const") &&
      node.declarations.every((item) => t.isIdentifier(item.id))
    ) {
      for (const item of node.declarations.toReversed())
        if (item.init != null) pending.push(item.init);
    } else break;
  }
  scopeExitSuspensions.set(block, null);
  return undefined;
};

/** Class keys complete before any static initializer or instance construction. */
const webSocketClassKeys = (node: t.Class): readonly t.Node[] => [
  ...(t.isNode(node.superClass) ? [node.superClass] : []),
  ...node.body.body.flatMap((member) =>
    (javaScriptClassField(member) || t.isClassMethod(member)) &&
    "computed" in member &&
    member.computed
      ? [member.key]
      : [],
  ),
];

const webSocketStaticInitializers = (member: t.Node): readonly t.Node[] =>
  t.isStaticBlock(member)
    ? member.body
    : javaScriptClassField(member) && member.static && t.isNode(member.value)
      ? [member.value]
      : [];

/** A definite throw enters a simple catch binding before its handler can run. */
const webSocketMandatoryHandler = (
  node: t.TryStatement,
): t.BlockStatement | undefined =>
  node.handler != null &&
  (node.handler.param == null || t.isIdentifier(node.handler.param)) &&
  syntaxAlwaysThrows(node.block)
    ? node.handler.body
    : undefined;

/** Children completed in order if this straight-line node completes normally. */
const webSocketOrderedEvaluation = (node: t.Node): readonly t.Node[] => {
  if (t.isBlockStatement(node)) {
    const reachable: t.Node[] = [];
    for (const statement of node.body) {
      reachable.push(statement);
      if (!syntaxMayCompleteNormally(statement)) break;
    }
    return reachable;
  }
  const operands =
    syntaxUnconditionalOperands(node) ?? syntaxEvaluationOperands(node);
  if (operands !== undefined) return operands;
  if (t.isLabeledStatement(node)) {
    const prefix: t.Node[] = [];
    for (const statement of t.isBlockStatement(node.body)
      ? node.body.body
      : [node.body]) {
      if (webSocketBodyMayJump(statement)) break;
      prefix.push(statement);
    }
    const exit = t.isBlockStatement(node.body)
      ? webSocketEveryExitSuspension(node.body)
      : undefined;
    return exit === undefined ? prefix : [...prefix, exit];
  }
  if (t.isWithStatement(node)) return [node.object, node.body];
  if (t.isClass(node))
    return [
      ...webSocketClassKeys(node),
      ...node.body.body.flatMap(webSocketStaticInitializers),
    ];
  if (t.isSwitchStatement(node)) return [node.discriminant];
  // Every normally completed loop evaluates its initial test, but its body
  // and updates may never execute. A do/while body precedes its first test.
  if (t.isWhileStatement(node)) return [node.test];
  if (t.isDoWhileStatement(node))
    return webSocketBodyMayJump(node.body)
      ? t.isBlockStatement(node.body)
        ? [webSocketEveryExitSuspension(node.body)].filter(
            (item) => item !== undefined,
          )
        : []
      : [node.body, node.test];
  if (t.isTryStatement(node))
    return [
      node.handler == null
        ? node.block
        : webSocketEveryExitSuspension(node.block),
      webSocketMandatoryHandler(node),
      node.finalizer,
    ].filter((item) => item != null);
  if (t.isForOfStatement(node) || t.isForInStatement(node)) return [node.right];
  if (t.isForStatement(node))
    return [node.init, node.test].filter((element) => element != null);
  if (t.isYieldExpression(node) && node.argument != null)
    return [node.argument];
  // Conditional/short-circuit branches, nested functions and try/catch do not
  // establish a suspension on every path to the following expression.
  return [];
};

const webSocketCompletedSuspensions = new WeakMap<
  JavaScriptSemanticAnalysisState,
  WeakMap<t.Node, WebSocketSuspension | null>
>();

/** Successful completion crosses the last suspension in this straight-line node. */
const webSocketCompletedSuspension = (
  node: t.Node,
  state: JavaScriptSemanticAnalysisState,
): WebSocketSuspension | undefined => {
  let cached = webSocketCompletedSuspensions.get(state);
  if (cached === undefined) {
    cached = new WeakMap();
    webSocketCompletedSuspensions.set(state, cached);
  }
  const existing = cached.get(node);
  if (existing !== undefined) return existing ?? undefined;
  const pending = [node];
  while (pending.length > 0) {
    const next = pending.pop();
    if (next === undefined) continue;
    const current = unwrapJavaScriptExpression(next).node;
    // Disposal belongs to successful scope exit, never the declaration point.
    if (
      t.isBlockStatement(current) &&
      current.body.some(
        (statement) =>
          t.isVariableDeclaration(statement) &&
          statement.kind === "await using",
      )
    ) {
      cached.set(node, current);
      return current;
    }
    const delegateOwner =
      t.isYieldExpression(current) && current.delegate
        ? webSocketSuspensionOwner(current, state)
        : undefined;
    if (
      t.isAwaitExpression(current) ||
      (t.isForOfStatement(current) && current.await) ||
      (t.isYieldExpression(current) &&
        (!current.delegate ||
          // Async delegation awaits the iterator result even when it is done;
          // synchronous delegation can finish without yielding at all.
          (t.isFunction(delegateOwner) && delegateOwner.async)))
    ) {
      cached.set(node, current);
      return current;
    }
    for (const child of webSocketOrderedEvaluation(current))
      pending.push(child);
  }
  cached.set(node, null);
  return undefined;
};

const webSocketSuspensionPrefixes = new WeakMap<
  JavaScriptSemanticAnalysisState,
  WeakMap<t.Node, ReadonlyMap<t.Node, WebSocketSuspension>>
>();

/** Index sibling phases once rather than rescan a suspended body per socket. */
const webSocketPrecedingSuspension = (
  parent: t.Node,
  child: t.Node,
  state: JavaScriptSemanticAnalysisState,
): WebSocketSuspension | undefined => {
  if (
    (t.isIfStatement(parent) || t.isConditionalExpression(parent)) &&
    (child === parent.consequent || child === parent.alternate)
  )
    return webSocketCompletedSuspension(parent.test, state);
  if (
    (t.isLogicalExpression(parent) ||
      (t.isAssignmentExpression(parent) &&
        ["&&=", "||=", "??="].includes(parent.operator))) &&
    child === parent.right
  )
    return webSocketCompletedSuspension(parent.left, state);
  if (t.isTryStatement(parent) && child === parent.finalizer) {
    const handler = webSocketMandatoryHandler(parent);
    return (
      (handler === undefined
        ? undefined
        : webSocketEveryExitSuspension(handler)) ??
      webSocketEveryExitSuspension(parent.block)
    );
  }
  if (
    t.isSwitchStatement(parent) &&
    parent.cases.includes(child as t.SwitchCase)
  )
    return webSocketCompletedSuspension(parent.discriminant, state);
  if (t.isSwitchCase(parent) && child !== parent.test && parent.test != null) {
    const selection = state.parentsByNode.get(parent);
    if (t.isSwitchStatement(selection)) {
      const index = selection.cases.indexOf(parent);
      const preceding = selection.cases[index - 1];
      // Earlier matching cases may fall through without evaluating this test.
      if (
        index === 0 ||
        (preceding !== undefined && !syntaxMayCompleteNormally(preceding))
      ) {
        const suspension = webSocketCompletedSuspension(parent.test, state);
        if (suspension !== undefined) return suspension;
      }
    }
  }
  // Executed optional children follow the mandatory receiver/callee, even
  // though skipped children cannot prove completion for following siblings.
  if (
    (t.isCallExpression(parent) || t.isOptionalCallExpression(parent)) &&
    parent.arguments.includes(child as t.Expression) &&
    javaScriptOptionalOperandsMayBeSkipped(parent)
  )
    return webSocketCompletedSuspension(parent.callee, state);
  if (
    t.isOptionalMemberExpression(parent) &&
    parent.computed &&
    child === parent.property
  )
    return webSocketCompletedSuspension(parent.object, state);
  if (
    t.isForOfStatement(parent) &&
    parent.await &&
    (child === parent.body || child === parent.left)
  )
    return parent;
  if (
    (t.isForOfStatement(parent) || t.isForInStatement(parent)) &&
    (child === parent.body || child === parent.left)
  )
    return webSocketCompletedSuspension(parent.right, state);
  if (
    (t.isWhileStatement(parent) || t.isForStatement(parent)) &&
    (child === parent.body ||
      (t.isForStatement(parent) && child === parent.update))
  )
    return (
      (t.isForStatement(parent) &&
      child === parent.update &&
      !webSocketBodyMayJump(parent.body)
        ? webSocketCompletedSuspension(parent.body, state)
        : undefined) ??
      (parent.test == null
        ? undefined
        : webSocketCompletedSuspension(parent.test, state)) ??
      (t.isForStatement(parent) && parent.init != null
        ? webSocketCompletedSuspension(parent.init, state)
        : undefined)
    );
  let byParent = webSocketSuspensionPrefixes.get(state);
  if (byParent === undefined) {
    byParent = new WeakMap();
    webSocketSuspensionPrefixes.set(state, byParent);
  }
  let prefixes = byParent.get(parent);
  if (prefixes === undefined) {
    const indexed = new Map<t.Node, WebSocketSuspension>();
    let awaited: WebSocketSuspension | undefined;
    for (const node of webSocketOrderedEvaluation(parent)) {
      if (awaited !== undefined) indexed.set(node, awaited);
      awaited = webSocketCompletedSuspension(node, state) ?? awaited;
    }
    byParent.set(parent, indexed);
    prefixes = indexed;
  }
  return prefixes.get(child);
};

/** Find a completed suspension on the containing straight-line evaluation path. */
const webSocketContinuation = (
  node: t.Node,
  body: t.Node,
  state: JavaScriptSemanticAnalysisState,
): WebSocketSuspension | undefined => {
  let current = node;
  while (current !== body) {
    const parent = state.parentsByNode.get(current);
    if (parent === undefined) return undefined;
    const awaited = webSocketPrecedingSuspension(parent, current, state);
    if (awaited !== undefined) return awaited;
    current = parent;
  }
  return undefined;
};

/** Find the literal class whose construction evaluates a field or constructor. */
const webSocketClassConstruction = (
  node: t.Node,
  state: JavaScriptSemanticAnalysisState,
): t.NewExpression | undefined => {
  const body = state.parentsByNode.get(node);
  const declaration =
    body === undefined ? undefined : state.parentsByNode.get(body);
  if (!t.isClassExpression(declaration)) return undefined;
  const invocation = webSocketImmediateInvocation(declaration, state);
  return t.isNewExpression(invocation) ? invocation : undefined;
};

/** Legacy decorator application follows its class's keys and static values. */
const webSocketDecoratedClass = (
  node: t.Decorator,
  state: JavaScriptSemanticAnalysisState,
): t.Class | undefined => {
  let parent = state.parentsByNode.get(node);
  while (parent !== undefined) {
    if (t.isClass(parent)) return parent;
    if (
      t.isProgram(parent) ||
      (t.isFunction(parent) &&
        !t.isClassMethod(parent) &&
        !t.isClassPrivateMethod(parent))
    )
      return undefined;
    parent = state.parentsByNode.get(parent);
  }
  return undefined;
};

interface WebSocketParameterResume {
  readonly parameter: t.ArrayPattern;
  readonly invocation:
    | t.CallExpression
    | t.OptionalCallExpression
    | t.NewExpression;
}

/** Select a potential reached callee without imposing completed-write validity. */
const webSocketSelectedCallee = (raw: t.Node): t.Node => {
  let node = unwrapJavaScriptExpression(raw).node;
  for (;;) {
    const selected = javaScriptExactResultOperand(node, () => true);
    if (selected === undefined) return node;
    node = unwrapJavaScriptExpression(selected).node;
  }
};

const immediateCallers = new WeakMap<
  JavaScriptSemanticAnalysisState,
  WeakMap<t.Node, t.Function | null>
>();

/** Reuse body activation ownership, caching only each requested callee subtree. */
const webSocketImmediateCaller = (
  call: t.Node,
  state: JavaScriptSemanticAnalysisState,
): t.Function | undefined => {
  let callers = immediateCallers.get(state);
  if (callers === undefined) {
    callers = new WeakMap();
    immediateCallers.set(state, callers);
  }
  const cached = callers.get(call);
  if (cached !== undefined) return cached ?? undefined;
  if (
    !t.isCallExpression(call) &&
    !t.isOptionalCallExpression(call) &&
    !t.isNewExpression(call)
  )
    return undefined;
  const pending: t.Node[] = [call.callee];
  while (pending.length > 0) {
    const node = pending.pop();
    if (node === undefined) continue;
    if (t.isFunction(node)) {
      const invocation =
        t.isClassMethod(node) && node.kind === "constructor"
          ? webSocketClassConstruction(node, state)
          : webSocketImmediateInvocation(node, state);
      if (invocation === call) {
        callers.set(call, node);
        return node;
      }
    }
    pending.push(...childNodes(node));
  }
  callers.set(call, null);
  return undefined;
};

/** Match a known literal invocation's positional argument, never an unknown spread offset. */
const webSocketParameterResume = (
  result: t.Node,
  state: JavaScriptSemanticAnalysisState,
): WebSocketParameterResume | undefined => {
  const parent = state.parentsByNode.get(result);
  const array = t.isArrayExpression(parent) ? parent : undefined;
  const call = array === undefined ? parent : state.parentsByNode.get(array);
  if (
    !t.isCallExpression(call) &&
    !t.isOptionalCallExpression(call) &&
    !t.isNewExpression(call)
  )
    return undefined;
  let callee = webSocketSelectedCallee(call.callee);
  const owner = webSocketImmediateCaller(call, state);
  if (owner === undefined) return undefined;
  const classBody = state.parentsByNode.get(owner);
  const literalClass = t.isClassBody(classBody)
    ? state.parentsByNode.get(classBody)
    : undefined;
  const value =
    t.isClassMethod(owner) &&
    owner.kind === "constructor" &&
    t.isClassExpression(literalClass)
      ? webSocketOuterExpression(literalClass, state)
      : webSocketOuterExpression(owner, state);
  const selection = webSocketFreshMethodSelection(owner, value, state);
  const callable = webSocketSelectedCallee(
    selection === undefined
      ? value
      : webSocketOuterExpression(selection, state),
  );
  let offset = 0;
  if (
    callee !== callable &&
    (t.isMemberExpression(callee) || t.isOptionalMemberExpression(callee))
  ) {
    const method = semanticStaticPropertyName(callee.property, callee.computed);
    if (method !== "call" && method !== "apply") return undefined;
    if (
      method === "apply"
        ? array === undefined || call.arguments[1] !== array
        : array !== undefined
    )
      return undefined;
    offset = method === "call" ? 1 : 0;
    callee = webSocketSelectedCallee(callee.object);
  } else if (array !== undefined) return undefined;
  // Bound argument lists need a separate positional proof; the activation alone
  // does not say which parameter receives this generator.
  if (callee !== callable) return undefined;
  const arguments_ = array?.elements ?? call.arguments;
  const index = arguments_.indexOf(result as t.Expression);
  if (
    index < offset ||
    arguments_.slice(0, index).some((argument) => t.isSpreadElement(argument))
  )
    return undefined;
  const parameter = runtimeFunctionParameters(owner)[index - offset];
  const pattern = t.isAssignmentPattern(parameter) ? parameter.left : parameter;
  return t.isArrayPattern(pattern) && pattern.elements.length > 0
    ? { parameter: pattern, invocation: call }
    : undefined;
};

/** Direct iteration, literal parameters and iterable spreads resume a fresh generator in-turn. */
const webSocketGeneratorResume = (
  invocation: t.Node,
  state: JavaScriptSemanticAnalysisState,
):
  | t.CallExpression
  | t.OptionalCallExpression
  | t.ForOfStatement
  | t.SpreadElement
  | t.ArrayPattern
  | t.YieldExpression
  | WebSocketParameterResume
  | undefined => {
  const result = webSocketOuterExpression(invocation, state, true);
  const member = state.parentsByNode.get(result);
  if (t.isForOfStatement(member) && member.right === result) return member;
  if (
    t.isYieldExpression(member) &&
    member.delegate &&
    member.argument === result
  )
    return member;
  const pattern =
    t.isVariableDeclarator(member) && member.init === result
      ? member.id
      : t.isAssignmentExpression(member) &&
          member.right === result &&
          member.operator === "="
        ? member.left
        : undefined;
  if (t.isArrayPattern(pattern) && pattern.elements.length > 0) return pattern;
  const parameter = webSocketParameterResume(result, state);
  if (parameter !== undefined) return parameter;
  if (t.isSpreadElement(member) && member.argument === result) {
    const consumer = state.parentsByNode.get(member);
    if (
      t.isArrayExpression(consumer) ||
      t.isCallExpression(consumer) ||
      t.isNewExpression(consumer)
    )
      return member;
  }
  if (
    (!t.isMemberExpression(member) && !t.isOptionalMemberExpression(member)) ||
    member.object !== result ||
    semanticStaticPropertyName(member.property, member.computed) !== "next"
  )
    return undefined;
  const callee = webSocketOuterExpression(member, state);
  const call = state.parentsByNode.get(callee);
  return (t.isCallExpression(call) || t.isOptionalCallExpression(call)) &&
    call.callee === callee
    ? call
    : undefined;
};

const bodySuspensionFacts = new WeakMap<t.Node, boolean>();
/** A synchronous iterator resumes in-turn unless its consumer body can await. */
const webSocketBodyMaySuspend = (body: t.Node): boolean => {
  const known = bodySuspensionFacts.get(body);
  if (known !== undefined) return known;
  const pending = [body];
  while (pending.length > 0) {
    const node = pending.pop();
    if (node === undefined) continue;
    if (
      t.isAwaitExpression(node) ||
      t.isYieldExpression(node) ||
      (t.isForOfStatement(node) && node.await) ||
      (t.isVariableDeclaration(node) && node.kind === "await using")
    ) {
      bodySuspensionFacts.set(body, true);
      return true;
    }
    if (t.isFunction(node)) {
      if ((t.isObjectMethod(node) || t.isClassMethod(node)) && node.computed)
        pending.push(node.key);
      continue;
    }
    pending.push(...childNodes(node));
  }
  bodySuspensionFacts.set(body, false);
  return false;
};

/** A delegated generator inherits the surrounding generator's actual consumer. */
const webSocketGeneratorConsumerStaysInTurn = (
  invocation: t.Node,
  read: t.Node,
  body: t.Node,
  state: JavaScriptSemanticAnalysisState,
  ownedResultEscape?: t.Node,
  seen = new Set<t.Node>(),
): boolean => {
  if (seen.has(invocation)) return false;
  seen.add(invocation);
  if (t.isSpreadElement(invocation)) return true;
  if (t.isArrayPattern(invocation))
    return !semanticPatternSuspendsBeforeGeneratorRead({
      read,
      body,
      pattern: invocation,
      state,
      ...(ownedResultEscape === undefined ? {} : { ownedResultEscape }),
      ordered: webSocketOrderedEvaluation,
      maySuspend: webSocketBodyMaySuspend,
      completedSuspension: (node) =>
        webSocketCompletedSuspension(node, state) !== undefined,
    });
  if (t.isForOfStatement(invocation))
    return (
      !invocation.await &&
      !webSocketBodyMaySuspend(invocation.left) &&
      !webSocketBodyMaySuspend(invocation.body)
    );
  if (t.isYieldExpression(invocation) && invocation.delegate) {
    const owner = webSocketSuspensionOwner(invocation, state);
    if (
      !t.isFunction(owner) ||
      t.isArrowFunctionExpression(owner) ||
      !owner.generator ||
      owner.async
    )
      return false;
    const call = webSocketImmediateInvocation(owner, state);
    const resume =
      call === undefined ? undefined : webSocketGeneratorResume(call, state);
    return (
      resume !== undefined &&
      webSocketGeneratorConsumerStaysInTurn(
        "parameter" in resume ? resume.parameter : resume,
        read,
        owner.body,
        state,
        call,
        seen,
      )
    );
  }
  return false;
};

/** The lexical body that actually suspends owns the continuation boundary. */
const webSocketSuspensionOwner = (
  node: t.Node,
  state: JavaScriptSemanticAnalysisState,
): t.Node => {
  let current: t.Node = node;
  for (;;) {
    const parent = state.parentsByNode.get(current);
    if (parent === undefined) return current;
    if (
      t.isFunction(parent) &&
      !(
        (t.isClassMethod(parent) || t.isObjectMethod(parent)) &&
        parent.key === current
      )
    )
      return parent;
    current = parent;
  }
};

/** A caller directly awaiting this result cannot initialize later locals yet. */
const webSocketWaitingContexts = (
  invocation: t.Node,
  state: JavaScriptSemanticAnalysisState,
): readonly SemanticExecutionFrame[] => {
  const contexts: SemanticExecutionFrame[] = [];
  const pending = [invocation];
  const seen = new Set<t.Node>();
  while (pending.length > 0) {
    const current = pending.pop();
    if (current === undefined || seen.has(current)) continue;
    seen.add(current);
    for (const awaited of semanticAwaitedResultSites(current, state, (node) =>
      webSocketExecutionContexts(node, state, true),
    )) {
      const owner = webSocketSuspensionOwner(awaited, state);
      contexts.push({ owner, point: awaited });
      if (t.isFunction(owner)) {
        const caller = webSocketImmediateInvocation(owner, state);
        if (caller !== undefined) pending.push(caller);
      }
    }
  }
  return contexts;
};

/** A lexical switch initializer is not reached by entering another case. */
export const webSocketInitializerDominatesRead = (
  initializer: t.Node,
  read: t.Node,
  state: JavaScriptSemanticAnalysisState,
  bindingNode?: t.Node,
): boolean => {
  return (
    semanticInitializerPrecedesRead({
      initializer,
      read,
      ...(bindingNode === undefined ? {} : { bindingNode }),
      parents: state.parentsByNode,
      initializerContexts: webSocketExecutionContexts(initializer, state),
      readContexts: webSocketExecutionContexts(read, state),
    }) ?? true
  );
};

const webSocketClassPrefixes = new WeakMap<
  JavaScriptSemanticAnalysisState,
  WeakMap<
    t.Class,
    {
      readonly keys: ReadonlyMap<t.Node, WebSocketSuspension | null>;
      readonly statics: ReadonlyMap<t.Node, WebSocketSuspension | null>;
    }
  >
>();

/** Index class evaluation once; all keys precede every static initializer. */
const webSocketClassPrefix = (
  member: t.Node,
  computedKey: boolean,
  state: JavaScriptSemanticAnalysisState,
): WebSocketSuspension | undefined => {
  const body = state.parentsByNode.get(member);
  const declaration =
    body === undefined ? undefined : state.parentsByNode.get(body);
  if (!t.isClass(declaration)) return undefined;
  let byClass = webSocketClassPrefixes.get(state);
  if (byClass === undefined) {
    byClass = new WeakMap();
    webSocketClassPrefixes.set(state, byClass);
  }
  let prefixes = byClass.get(declaration);
  if (prefixes === undefined) {
    const keys = new Map<t.Node, WebSocketSuspension | null>();
    const statics = new Map<t.Node, WebSocketSuspension | null>();
    let suspended = t.isNode(declaration.superClass)
      ? webSocketCompletedSuspension(declaration.superClass, state)
      : undefined;
    for (const item of declaration.body.body) {
      keys.set(item, suspended ?? null);
      if (
        (javaScriptClassField(item) || t.isClassMethod(item)) &&
        "computed" in item &&
        item.computed
      )
        suspended = webSocketCompletedSuspension(item.key, state) ?? suspended;
    }
    for (const item of declaration.body.body) {
      statics.set(item, suspended ?? null);
      for (const initializer of webSocketStaticInitializers(item))
        suspended =
          webSocketCompletedSuspension(initializer, state) ?? suspended;
    }
    prefixes = { keys, statics };
    byClass.set(declaration, prefixes);
  }
  return (
    (computedKey ? prefixes.keys : prefixes.statics).get(member) ?? undefined
  );
};

/**
 * Keep local initialization ordered across suspension phases. A suspension cuts
 * off outer execution frames only after retaining the body that owns it. Calls
 * evaluate callee/arguments before bodies; classes evaluate keys, static values,
 * and construction arguments before instance fields and constructor bodies.
 */
export const webSocketExecutionContexts = (
  node: t.Node,
  state: JavaScriptSemanticAnalysisState,
  directOnly = false,
): readonly SemanticExecutionFrame[] => {
  const contexts: SemanticExecutionFrame[] = [];
  let point = node;
  let suspendedOwner: t.Node | undefined;
  const suspendedAt = (suspension: WebSocketSuspension | undefined): void => {
    if (suspension !== undefined)
      suspendedOwner = webSocketSuspensionOwner(suspension, state);
  };
  const suspendedAfter = (evaluated: t.Node): void =>
    suspendedAt(webSocketCompletedSuspension(evaluated, state));
  let current = node;
  for (;;) {
    const parent = state.parentsByNode.get(current);
    if (parent === undefined) return [...contexts, { owner: current, point }];
    if (javaScriptClassField(parent) && parent.value === current) {
      if (parent.static)
        suspendedAt(webSocketClassPrefix(parent, false, state));
      else {
        const construction = webSocketClassConstruction(parent, state);
        if (construction === undefined)
          return [...contexts, { owner: parent, point }];
        suspendedAfter(construction);
      }
    }
    if (
      (javaScriptClassField(parent) || t.isClassMethod(parent)) &&
      "computed" in parent &&
      parent.computed &&
      parent.key === current
    )
      suspendedAt(webSocketClassPrefix(parent, true, state));
    if (t.isStaticBlock(parent))
      suspendedAt(webSocketClassPrefix(parent, false, state));
    if (t.isFunction(parent)) {
      if (
        (t.isObjectMethod(parent) || t.isClassMethod(parent)) &&
        parent.key === current
      ) {
        current = parent;
        continue;
      }
      let invocation:
        | ReturnType<typeof webSocketImmediateInvocation>
        | t.ForOfStatement
        | t.SpreadElement
        | t.ArrayPattern
        | t.YieldExpression =
        t.isClassMethod(parent) && parent.kind === "constructor"
          ? webSocketClassConstruction(parent, state)
          : webSocketImmediateInvocation(parent, state);
      contexts.push({ owner: parent, point });
      const generatorBody =
        current === parent.body &&
        !t.isArrowFunctionExpression(parent) &&
        parent.generator;
      const generatorInvocation = invocation;
      let parameterConsumer: t.ArrayPattern | undefined;
      if (
        generatorBody &&
        invocation !== undefined &&
        !t.isNewExpression(invocation)
      ) {
        const resume = webSocketGeneratorResume(invocation, state);
        parameterConsumer =
          resume !== undefined && "parameter" in resume
            ? resume.parameter
            : undefined;
        invocation =
          resume !== undefined && "parameter" in resume
            ? resume.invocation
            : resume;
      }
      if (invocation === undefined) return contexts;
      const decoratedClass = t.isDecorator(invocation)
        ? webSocketDecoratedClass(invocation, state)
        : undefined;
      if (t.isOptionalCallExpression(invocation)) {
        // Reaching this literal body proves the optional call was taken.
        // Its argument evaluation therefore precedes body entry.
        for (const operand of [invocation.callee, ...invocation.arguments])
          suspendedAfter(operand);
      } else if (
        (t.isObjectMethod(parent) || t.isClassMethod(parent)) &&
        parent.kind === "set"
      ) {
        const site = semanticValueWriteSite(invocation, state.parentsByNode);
        if (site !== undefined) {
          // RHS and preceding pattern slots finish before the selected write,
          // whereas later slots must not defer this setter activation.
          suspendedAt(webSocketContinuation(invocation, site, state));
          if (t.isAssignmentExpression(site)) {
            suspendedAfter(site.right);
            if (
              semanticPatternSuspendsBeforeTarget(
                site.left,
                site.right,
                invocation,
                state,
                (operand) =>
                  webSocketCompletedSuspension(operand, state) !== undefined,
              )
            )
              suspendedOwner = webSocketSuspensionOwner(site, state);
          }
          if (t.isForOfStatement(site) && site.await) suspendedAt(site);
        }
        suspendedAfter(invocation);
      } else if (!t.isArrayPattern(invocation)) {
        suspendedAfter(
          t.isForOfStatement(invocation)
            ? invocation.right
            : t.isYieldExpression(invocation)
              ? (invocation.argument ?? invocation)
              : (decoratedClass ?? invocation),
        );
      }
      if (
        (parent.async || generatorBody) &&
        current === parent.body &&
        // Synchronous for-of resumes after every ordinary yield in the same turn.
        !(
          !parent.async &&
          generatorBody &&
          webSocketGeneratorConsumerStaysInTurn(
            parameterConsumer ?? invocation,
            node,
            parent.body,
            state,
            generatorInvocation,
          )
        )
      ) {
        const continuation = webSocketContinuation(node, parent.body, state);
        if (continuation !== undefined)
          suspendedOwner = webSocketSuspensionOwner(continuation, state);
      }
      // Direct frames are an earlier invocation bound for alias initialization.
      // They do not consult the waiting index that is currently being built.
      if (suspendedOwner === parent && !directOnly)
        return [...contexts, ...webSocketWaitingContexts(invocation, state)];
      point = invocation;
      // A returned callable executes outside the getter's completed activation.
      if (webSocketReturnedGetter(parent, state) !== undefined) {
        current = invocation;
        continue;
      }
      // Method/parameter decorator metadata is evaluated with the class, not
      // within the decorated method's runtime activation.
      if (decoratedClass !== undefined) {
        current = decoratedClass;
        continue;
      }
    }
    current = parent;
  }
};
