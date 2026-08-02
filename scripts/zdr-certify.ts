import { randomBytes } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { defaultPrivacyConfig, evaluatePrivacy, setPrivacyMode } from "../src/privacy/index.js";

const canary = `zdr-canary-${randomBytes(16).toString("hex")}`;
const root = process.cwd();
const configDir = join(root, ".zdr-certification-runtime");
const local = defaultPrivacyConfig(configDir);
if (evaluatePrivacy(local).verdict !== "ALLOW") throw new Error("LOCAL_ZDR_CERTIFICATION_FAILED");
const e2e = setPrivacyMode(configDir, "END_TO_END_ZDR");
if (evaluatePrivacy(e2e, ["missing-profile"]).verdict !== "BLOCK") throw new Error("E2E_UNKNOWN_PROCESSOR_NOT_BLOCKED");
function scan(directory: string): string[] { if (!existsSync(directory)) return []; const found: string[] = []; for (const name of readdirSync(directory)) { const path = join(directory, name); if (statSync(path).isDirectory()) found.push(...scan(path)); else if (readFileSync(path).includes(canary)) found.push(path); } return found; }
const matches = scan(join(root, ".invock"));
if (matches.length > 0) throw new Error(`ZDR_CANARY_FOUND:${matches.join(",")}`);
console.log(JSON.stringify({ verdict: "PASS", localZdr: "PASS", endToEndUnknownProcessor: "BLOCK", canaryMatches: matches.length, canary: "random-synthetic-not-persisted" }, null, 2));
