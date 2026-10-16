import {
  inspectJvmDebugMetadataInputSchema,
  javaDebugMetadataResultSchema,
} from "../../domain/jvm/javaDebugMetadataReport.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Static JVM debug-readiness inspection of one selected local class file. */
export const INSPECT_JVM_DEBUG_METADATA_CONTRACT = {
  name: "inspect_jvm_debug_metadata",
  ...toolContractMetadata("inspect_jvm_debug_metadata"),
  kind: "artifact-provider",
  description:
    "Inspect compiler-emitted debug metadata in one selected local JVM .class file, or one class entry selected from a local .jar, to judge debugging readiness before attaching a debugger. Reads SourceFile, SourceDebugExtension, LineNumberTable, LocalVariableTable and LocalVariableTypeTable and binds bytecode offsets, local slots and scope ranges to each method's name and descriptor. Classifies every method as present, partial, stripped, malformed or not-applicable, flags out-of-range scopes, and reports examined coverage. For a JAR, pass entry (the class member path) and optionally release to select a multi-release override; selection is explicit and never silently combines versions. Decompiler line numbers are not substituted for compiler positions. No Java executes; no source URL is resolved; supplied source is never claimed to match a SourceFile name. SourceDebugExtension is preserved opaquely. SHA-256 identifies the exact selected bytes, not authenticity.",
  inputSchema: inspectJvmDebugMetadataInputSchema,
  outputSchema: evidenceResultOf(javaDebugMetadataResultSchema),
  examples: [
    {
      title: "Inspect a selected local class file for debug readiness",
      input: { path: "/artifacts/Example.class" },
    },
    {
      title: "Inspect a multi-release class entry inside a JAR",
      input: {
        path: "/artifacts/app.jar",
        entry: "com/example/Service.class",
        release: 17,
      },
    },
  ],
} as const satisfies ToolContract;

/** Keep the public catalog in its existing order, using its named contract. */
export const JVM_TOOL_CONTRACTS = [
  INSPECT_JVM_DEBUG_METADATA_CONTRACT,
] as const;
