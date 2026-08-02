import { resolve } from "node:path";
import { generateSupplyChainSigningMaterial, scanSupplyChain, verifySupplyChainSignature } from "../src/supplychain/index.js";

const rawArgs = process.argv.slice(2);
const args = rawArgs[0] === "--" ? rawArgs.slice(1) : rawArgs;
const rootFlag = args.indexOf("--root");
const selected = rootFlag >= 0 ? args[rootFlag + 1] : undefined;
const signReport = args.includes("--sign");
const allowed = new Set(["--sign", "--root"]);
if (args.some(arg => !allowed.has(arg) && (rootFlag < 0 || arg !== selected)) || (rootFlag >= 0 && (!selected || args.length !== rootFlag + 2 + (signReport ? 1 : 0)))) throw new Error("supply-chain accepts --root <path> and optional --sign");
const report = scanSupplyChain(resolve(selected ?? process.cwd()), signReport ? { signing: generateSupplyChainSigningMaterial() } : {});
if (signReport && (!report.signature || report.signatureStatus !== "verified" || !verifySupplyChainSignature(report))) throw new Error("SUPPLY_CHAIN_SIGNATURE_VERIFICATION_FAILED");
console.log(JSON.stringify(report, null, 2));
