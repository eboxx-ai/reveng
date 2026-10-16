import { z } from "incur";
import { resolve } from "node:path";
import type { Logger } from "pino";

import { apkSignatureModule } from "../composition/apkSignature.js";
import { logCliCommand } from "../cliLogging.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";

/** Resolve the caller-selected APK through the shared workflow. */
export const registerApkSignatureCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<NodeJS.ProcessEnv>,
): void => {
  const service = apkSignatureModule.create(environment);
  cli.command(apkSignatureModule.cliCommand, {
    description:
      "Inspect the signature schemes (v1/v2/v3/v3.1) of a selected local APK/ZIP/AAB",
    args: z.object({
      path: z.string().describe("Local .apk/.zip/.aab artifact to inspect"),
    }),
    options: z.object({}),
    run: ({ args }) =>
      withCommandCancellation(async (signal) => {
        try {
          return await logCliCommand(
            logger,
            apkSignatureModule.cliCommand,
            async () => {
              const result = await service.inspect(
                { path: resolve(args.path) },
                { signal },
              );
              return result.ok
                ? result.value
                : projectAnalysisError(result.error);
            },
          );
        } finally {
          await service.close();
        }
      }),
  });
};
