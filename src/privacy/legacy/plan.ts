import { sign, verify } from "node:crypto";
import { digestJson } from "../../core/canonical.js";
import { type LegacyRemediationPlan } from "./types.js";

export function signPlan(
  unsignedPlan: Omit<LegacyRemediationPlan, "digest" | "keyId" | "signature">,
  privateKeyPem: string,
  keyId: string
): LegacyRemediationPlan {
  const digest = digestJson(unsignedPlan);
  const signature = sign(
    null,
    Buffer.from(`invock-remediation-plan-v1\0${digest}`, "utf8"),
    privateKeyPem
  ).toString("base64url");

  return {
    ...unsignedPlan,
    digest,
    keyId,
    signature,
  };
}

export function verifyPlan(
  plan: LegacyRemediationPlan,
  publicKeyPem: string
): boolean {
  try {
    const unsignedPlan = {
      id: plan.id,
      scanId: plan.scanId,
      scanDigest: plan.scanDigest,
      createdAt: plan.createdAt,
      items: plan.items,
      selectedDeleteCount: plan.selectedDeleteCount,
      manualActionCount: plan.manualActionCount,
      providerActionCount: plan.providerActionCount,
      ignoredCount: plan.ignoredCount,
    };
    const expectedDigest = digestJson(unsignedPlan);
    if (plan.digest !== expectedDigest) {
      return false;
    }
    return verify(
      null,
      Buffer.from(`invock-remediation-plan-v1\0${plan.digest}`, "utf8"),
      publicKeyPem,
      Buffer.from(plan.signature, "base64url")
    );
  } catch {
    return false;
  }
}
