import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { generateSupplyChainSigningMaterial, createCycloneDx15Document, scanSupplyChain, validateCycloneDx15, verifySupplyChainSignature } from "../src/supplychain/index.js";

const rawArgs = process.argv.slice(2);
const args = rawArgs[0] === "--" ? rawArgs.slice(1) : rawArgs;
const rootFlag = args.indexOf("--root");
const selected = rootFlag >= 0 ? args[rootFlag + 1] : undefined;
const signReport = args.includes("--sign");
const advisoryStatusFlag = args.indexOf("--advisory-status");
const advisoryEvidenceFlag = args.indexOf("--advisory-evidence");
const cyclonedxFlag = args.indexOf("--cyclonedx-out");
const advisoryStatus = advisoryStatusFlag >= 0 ? args[advisoryStatusFlag + 1] as "queried-no-findings" | "queried-findings" | "query-failed" : undefined;
const advisoryEvidence = advisoryEvidenceFlag >= 0 ? args[advisoryEvidenceFlag + 1] : undefined;
const cyclonedxOut = cyclonedxFlag >= 0 ? args[cyclonedxFlag + 1] : undefined;
const valueFlags = new Set(["--root", "--advisory-status", "--advisory-evidence", "--cyclonedx-out"]);
const consumedValues = new Set([selected, advisoryStatus, advisoryEvidence, cyclonedxOut]);
if (args.some(arg => !["--sign", ...valueFlags].includes(arg) && !consumedValues.has(arg)) || [rootFlag, advisoryStatusFlag, advisoryEvidenceFlag, cyclonedxFlag].some(index => index >= 0 && (!args[index + 1] || args[index + 1]?.startsWith("--")))) throw new Error("supply-chain accepts --root, --sign, --advisory-status, --advisory-evidence, and --cyclonedx-out");
if (advisoryStatus !== undefined && advisoryEvidence === undefined) throw new Error("--advisory-status requires --advisory-evidence");
if (advisoryStatus === undefined && advisoryEvidence !== undefined) throw new Error("--advisory-evidence requires --advisory-status");
if (advisoryStatus !== undefined && !["queried-no-findings", "queried-findings", "query-failed"].includes(advisoryStatus)) throw new Error("--advisory-status is invalid");
if (advisoryEvidence !== undefined && !/^[A-Za-z0-9_-]{43}$/u.test(advisoryEvidence)) throw new Error("--advisory-evidence must be a SHA-256 digest");
const root = resolve(selected ?? process.cwd());
const report = scanSupplyChain(root, { ...(signReport ? { signing: generateSupplyChainSigningMaterial() } : {}), ...(advisoryStatus && advisoryEvidence ? { advisory: { status: advisoryStatus, evidenceDigest: advisoryEvidence } } : {}) });
if (signReport && (!report.signature || report.signatureStatus !== "verified" || !verifySupplyChainSignature(report))) throw new Error("SUPPLY_CHAIN_SIGNATURE_VERIFICATION_FAILED");
if (cyclonedxOut) {
  const document = createCycloneDx15Document(report.sbom);
  if (!validateCycloneDx15(document)) throw new Error("CYCLONEDX_1_5_VALIDATION_FAILED");
  writeFileSync(resolve(cyclonedxOut), JSON.stringify(document, null, 2) + "\n", { mode: 0o600 });
}
console.log(JSON.stringify(report, null, 2));
