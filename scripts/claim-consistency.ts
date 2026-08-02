import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";

const requiredArtifacts = [
  "THREAT_MODEL.md", "AUTHORITY_CALCULUS.md", "SYSTEM_CARD.md",
];
const args = process.argv.slice(2);
const countFlag = args.indexOf("--test-count");
const verdictFlag = args.indexOf("--final-verdict");
function discoverTestCount(): number {
  const result = spawnSync("pnpm", ["test"], { encoding: "utf8", env: { ...process.env, INVOCK_TEST_MODE: "1" }, timeout: 180_000, killSignal: "SIGKILL", stdio: ["ignore", "pipe", "pipe"] });
  if (result.status !== 0) throw new Error(`CLAIM_CONSISTENCY_TEST_SUITE_FAILED${result.stderr ? `: ${result.stderr.trim()}` : ""}`);
  const count = /^# tests (\d+)$/mu.exec(`${result.stdout}\n${result.stderr}`)?.[1];
  if (!count) throw new Error("CLAIM_CONSISTENCY_TEST_COUNT_MISSING");
  return Number(count);
}
const testCount = countFlag >= 0 ? Number(args[countFlag + 1]) : discoverTestCount();
const finalVerdict = verdictFlag >= 0 ? args[verdictFlag + 1] : "NOT_READY";
if (!Number.isInteger(testCount) || testCount <= 0) throw new Error("CLAIM_CONSISTENCY_REQUIRES_TEST_COUNT");
if (finalVerdict !== "READY" && finalVerdict !== "NOT_READY") throw new Error("CLAIM_CONSISTENCY_REQUIRES_VERDICT");

const findings: string[] = [];
for (const artifact of requiredArtifacts) {
  if (!existsSync(artifact) || statSync(artifact).size === 0) findings.push(`missing-artifact:${artifact}`);
}

function markdownFiles(directory: string): string[] {
  if (!existsSync(directory)) return [];
  const files: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...markdownFiles(path));
    else if (entry.name.endsWith(".md")) files.push(path);
  }
  return files;
}

const documents = [...readdirSync(".").filter(file => file.endsWith(".md")), ...markdownFiles("docs")];
const historical = /historical|superseded|stale|older|prior run|previous|baseline|not current|not authoritative|predat|earlier|recorded audit/iu;
for (const document of documents) {
  const lines = readFileSync(document, "utf8").split(/\r?\n/u);
  const documentHistorical = /(?:^|\n)\s*(?:#|>)\s*(?:historical|superseded|archived|prior|older|not current|not authoritative|stale)\b/iu.test(lines.slice(0, 20).join("\n"));
  lines.forEach((line, index) => {
    const location = `${document}:${index + 1}`;
    const historicalLine = documentHistorical || historical.test(line);
    // Checklist labels such as "Stage 1 tests pass" are stage identifiers,
    // not claims about the repository test total.
    const stageChecklistLine = /\bStage\s+\d+\b.*\btests?\b/iu.test(line);
    const testCountMatches = stageChecklistLine ? [] : [...line.matchAll(/\b(\d+)\s*(?:tests?|passing|passed)\b/giu)];
    if (testCountMatches.some(match => Number(match[1]) !== testCount) && !historicalLine) findings.push(`${location}:stale-test-count`);
    const countMatches = [...line.matchAll(/\b(\d+)\s*\/\s*(\d+)\b/gu)];
    for (const match of countMatches) {
      const context = line.slice(Math.max(0, (match.index ?? 0) - 48), (match.index ?? 0) + match[0].length + 64);
      if (/(?:pnpm\s+test|full\s+(?:repository\s+)?suite|test\s+count|tests?\s+(?:pass|passed|passing))/iu.test(context) && (Number(match[1]) !== testCount || Number(match[2]) !== testCount) && !historicalLine) {
        findings.push(`${location}:current-count-mismatch`);
        break;
      }
    }
    if (finalVerdict === "NOT_READY" && /(?:INVOCK PRODUCT TRANSFORMATION: READY|VERDICT:\s*READY FOR HACKATHON)/iu.test(line) && !historicalLine) findings.push(`${location}:ready-claim-with-open-gate`);
    if (finalVerdict === "NOT_READY" && /Independent audits:\s*5\s*\/\s*5\s*PASS/iu.test(line) && !historicalLine) findings.push(`${location}:unearned-audit-claim`);
  });
}

if (findings.length > 0) {
  console.error(`INVOCK CLAIM CONSISTENCY: FAIL\n${findings.join("\n")}`);
  process.exitCode = 1;
} else {
  console.log(`INVOCK CLAIM CONSISTENCY: PASS\nDocuments scanned: ${documents.length}\nTest count cross-check: ${testCount}\nFinal verdict boundary: ${finalVerdict}`);
}
