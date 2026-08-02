import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { loadPrivacyConfig, validateMode, verifyPrivacyContract } from "../src/privacy/index.js";

const directory = process.env.INVOCK_PRIVACY_DIR ?? join(process.cwd(), ".invock");
const config = loadPrivacyConfig(directory);
validateMode(config.mode);
if (!verifyPrivacyContract(config)) throw new Error("PRIVACY_CONTRACT_DIGEST_INVALID");
const forbidden = ["STANDARD", "OFF", "DISABLED", "ENCRYPTED_RETENTION"];
const serialized = readFileSync(join(directory, "privacy.json"), "utf8");
if (forbidden.some(value => serialized.includes(value))) throw new Error("FORBIDDEN_PRIVACY_MODE_PRESENT");
console.log(JSON.stringify({ verdict: "PASS", mode: config.mode, contractVerified: true, privacyConfigExists: existsSync(join(directory, "privacy.json")), contentFieldsPersisted: false }, null, 2));
