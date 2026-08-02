import { runLegacyScan } from "./scanners.js";
import { type LocalLegacyState } from "./types.js";
import { loadPrivacyConfig, verifyPrivacyContract } from "../index.js";

export async function runLegacyVerification(
  workspaceRoot: string,
  selectedScopes: any[],
  deletedPathHmacs: string[]
): Promise<LocalLegacyState> {
  // 1. Rescan selected scopes
  const { findings } = await runLegacyScan(workspaceRoot, {
    consent: true,
    selectedScopes,
  });

  // 2. Verify deleted path HMACs are absent
  const deletedStillPresent = findings.some(f => deletedPathHmacs.includes(f.pathHmac));
  if (deletedStillPresent) {
    return "UNRESOLVED";
  }

  // 3. Verify ZDR certification state remains valid
  const config = loadPrivacyConfig(workspaceRoot);
  if (!verifyPrivacyContract(config)) {
    return "UNRESOLVED";
  }

  // 4. Determine state
  if (findings.length > 0) {
    return "PARTIALLY_REMEDIATED";
  }

  return "VERIFIED_CLEAN_FOR_SELECTED_SCOPE";
}
