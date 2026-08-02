import { cpSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";

interface Mutation { id: string; file: string; needle: string; replacement: string; test: string; }
const root = process.cwd();
const mutations: Mutation[] = [
  { id: "redirect-cross-host", file: "src/net/index.ts", needle: "if (next.hostname !== current.hostname && !policy.allowCrossHost)", replacement: "if (false && next.hostname !== current.hostname && !policy.allowCrossHost)", test: "test/net.test.ts" },
  { id: "lease-tool-boundary", file: "src/authority/evaluate.ts", needle: "if (leaf && request.tool && !leaf.constraints.tools.includes(request.tool))", replacement: "if (leaf && false && request.tool && !leaf.constraints.tools.includes(request.tool))", test: "test/authority/authority.test.ts" },
  { id: "arena-adapter-dispatch", file: "src/arena/index.ts", needle: "execute ? validateResult(await execute(scenario, context), scenario.id) : validateResult(await scenario.invoke(context), scenario.id)", replacement: "validateResult(await scenario.invoke(context), scenario.id)", test: "test/arena/arena.test.ts" },
];

const results: Array<{ id: string; killed: boolean; status: number | null }> = [];
for (const mutation of mutations) {
  const directory = mkdtempSync(join(tmpdir(), `invock-mut-${mutation.id}-`));
  try {
    cpSync(join(root, "src"), join(directory, "src"), { recursive: true });
    cpSync(join(root, "test"), join(directory, "test"), { recursive: true });
    symlinkSync(join(root, "node_modules"), join(directory, "node_modules"), "dir");
    const path = join(directory, mutation.file);
    const source = readFileSync(path, "utf8");
    if (!source.includes(mutation.needle)) throw new Error(`Mutation needle missing: ${mutation.id}`);
    writeFileSync(path, source.replace(mutation.needle, mutation.replacement));
    const command = spawnSync(process.execPath, ["--import", "tsx", "--test", mutation.test], { cwd: directory, encoding: "utf8" });
    results.push({ id: mutation.id, killed: command.status !== 0, status: command.status });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

console.log(JSON.stringify({ mutations: results, killed: results.filter(item => item.killed).length, total: results.length }));
if (results.some(item => !item.killed)) process.exitCode = 1;
