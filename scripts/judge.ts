import { once } from "node:events";
import { runJudge, type JudgeCheckpoint, type JudgeMode } from "../src/judge/index.js";

const args = new Set(process.argv.slice(2));
if (args.has("--help") || args.has("-h")) {
  console.log("Usage: pnpm judge [--automated|--presentation]\n\nDefault mode is automated JSON. Presentation mode pauses at checkpoints only when stdin is a TTY.");
  process.exit(0);
}

const mode: JudgeMode = args.has("--presentation") ? "presentation" : "automated";
const pause = async (item: JudgeCheckpoint): Promise<void> => {
  if (!process.stdin.isTTY) return;
  process.stderr.write("CHECKPOINT " + item.id + ": " + item.label + " (" + item.status + "). Press Enter to continue.\n");
  process.stdin.resume();
  await once(process.stdin, "data");
};

try {
  const result = await runJudge({ mode, pause });
  process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  if (result.overall === "failed") process.exitCode = 1;
} catch (error) {
  process.stdout.write(JSON.stringify({ schemaVersion: "invock/judge-result/v1", command: "judge", mode, overall: "failed", error: error instanceof Error ? error.message : "JUDGE_FAILED" }) + "\n");
  process.exitCode = 1;
}
