import type {
  AnalysisExecution,
  ExecutionOptions,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { InspectJvmDebugMetadataInput } from "../../domain/jvm/javaDebugMetadataReport.js";
import type { EvidenceSubjectTarget } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";

/** Successful JVM inspection identifies the selected local file: a class file or its JAR. */
export type JvmDebugMetadataExecution = Omit<AnalysisExecution, "subject"> & {
  readonly subject: EvidenceSubjectTarget & { readonly format: "file" | "zip" };
};

/** Replaceable offline class-file reader, independent of target execution and network clients. */
export interface JvmDebugMetadataPort {
  /** Retry removal of any retained resources; failures preserve ownership for another attempt. */
  close(): Promise<void>;
  inspect(
    input: InspectJvmDebugMetadataInput,
    options?: ExecutionOptions,
  ): Promise<Result<JvmDebugMetadataExecution, AnalysisError>>;
}
