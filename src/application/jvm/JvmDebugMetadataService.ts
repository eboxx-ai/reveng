import { isAbsolute } from "node:path";

import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { JvmDebugMetadataPort } from "./JvmDebugMetadataPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  inspectJvmDebugMetadataInputSchema,
  javaDebugMetadataMatchesSubject,
  javaDebugMetadataResultSchema,
} from "../../domain/jvm/javaDebugMetadataReport.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { err, ok, type Result } from "../../domain/result.js";

const OPERATION = "inspect_jvm_debug_metadata";

/** Shared artifact validation and typed inline Evidence for CLI/MCP. */
export class JvmDebugMetadataService {
  constructor(readonly provider: JvmDebugMetadataPort) {}

  /** Join provider cleanup during shutdown or an explicit retry. */
  close(): Promise<void> {
    return this.provider.close();
  }

  /** Preserve exact selected artifact identity and the decoded debug facts. */
  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = inspectJvmDebugMetadataInputSchema.safeParse(rawInput);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(OPERATION, input.error.issues, rawInput, {
          cause: input.error,
        }),
      );
    if (!isAbsolute(input.data.path))
      return err(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: ["path"],
            reason: "invalid_format",
            message: "Expected an absolute filesystem path on this host.",
          },
        ]),
      );
    const inspected = await this.provider.inspect(input.data, options);
    if (!inspected.ok) return inspected;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const execution = inspected.value;
    const report = javaDebugMetadataResultSchema.safeParse(execution.result);
    if (
      !report.success ||
      report.data.artifact.path !== input.data.path ||
      !javaDebugMetadataMatchesSubject(report.data.artifact, execution.subject)
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "JVM class-file reader returned malformed data or changed the selected artifact identity.",
        ),
      );
    return ok(
      createEvidence(execution.subject, execution.provider, {
        operation: OPERATION,
        parameters: {
          path: input.data.path,
          ...(input.data.entry === undefined
            ? {}
            : { entry: input.data.entry }),
          ...(input.data.release === undefined
            ? {}
            : { release: input.data.release }),
        },
        result: report.data,
        ...(execution.rawResult === null
          ? {}
          : { rawResult: execution.rawResult }),
        confidence: "observed",
        locations: execution.locations,
        limitations: execution.limitations,
      }),
    );
  }
}
