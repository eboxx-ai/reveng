import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { ApkSignatureService } from "../application/apkSignature/ApkSignatureService.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { analysisInputErrorFromIssues } from "../domain/inputIssueProjection.js";
import { err } from "../domain/result.js";
import { apkSignatureModule } from "../composition/apkSignature.js";
import type { Logger } from "pino";
import { createEvidenceToolHandler } from "./contractToolHandler.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

/** Bind the named APK-signature contract to shared validation and session Evidence. */
export const registerApkSignatureTools = (
  server: EvidenceMcpServer,
  service: Pick<ApkSignatureService, "inspect">,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
): void => {
  const contract = apkSignatureModule.contract;
  const handler = createEvidenceToolHandler(
    server,
    async (rawInput, options) => {
      const parsed = contract.inputSchema.safeParse(rawInput);
      if (!parsed.success)
        return err(
          analysisInputErrorFromIssues(
            contract.name,
            parsed.error.issues,
            rawInput,
            { cause: parsed.error },
          ),
        );
      return service.inspect(parsed.data, options);
    },
    logger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  server.registerTool(
    contract.name,
    toolRegistrationOptions(contract),
    handler(contract),
  );
};
