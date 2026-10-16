import { JvmDebugMetadataService } from "../application/jvm/JvmDebugMetadataService.js";
import { JvmClassFileProvider } from "../jvm/JvmClassFileProvider.js";
import { INSPECT_JVM_DEBUG_METADATA_CONTRACT } from "../contracts/jvm/jvmToolContracts.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";

/** Compose the in-process class-file reader without acquisition or import-time I/O. */
export const createJvmDebugMetadataService = (): JvmDebugMetadataService =>
  new JvmDebugMetadataService(new JvmClassFileProvider());

/**
 * Static descriptor binding the one JVM debug-metadata operation for CLI/MCP.
 * Construction performs no acquisition or target I/O.
 */
export const jvmDebugMetadataModule = {
  contract: INSPECT_JVM_DEBUG_METADATA_CONTRACT,
  cliCommand: CLI_COMMANDS.inspectJvmDebugMetadata,
  create(
    _environment: Readonly<NodeJS.ProcessEnv>,
    injected?: JvmDebugMetadataService,
  ): Pick<JvmDebugMetadataService, "inspect" | "close"> {
    const service = injected ?? createJvmDebugMetadataService();
    return {
      inspect: service.inspect.bind(service),
      close: service.close.bind(service),
    };
  },
} as const;
