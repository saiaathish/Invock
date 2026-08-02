import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const roots = ["src", "scripts", "sdk"];
const extensions = new Set([".ts", ".tsx", ".js", ".py"]);
const violations: string[] = [];
let scanned = 0;

function walk(directory: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...walk(path));
    else if (extensions.has(path.slice(path.lastIndexOf(".")))) files.push(path);
  }
  return files;
}

for (const root of roots) {
  const files = walk(root);
  if (files.length === 0) throw new Error(`LINT_ROOT_EMPTY:${root}`);
  for (const file of files) {
    scanned += 1;
    if (file === "scripts/lint.ts") continue;
    const lines = readFileSync(file, "utf8").split(/\r?\n/u);
    lines.forEach((line, index) => {
      if (/\bdebugger\b/u.test(line)) violations.push(`${file}:${index + 1}:debugger`);
      if (/\b(?:TODO|FIXME)\b/u.test(line)) violations.push(`${file}:${index + 1}:unfinished-marker`);
      if (/\|\|\s*true\b/u.test(line)) violations.push(`${file}:${index + 1}:swallowed-error`);
    });
  }
}

if (violations.length > 0) {
  console.error(`INVOCK LINT: FAIL\n${violations.join("\n")}`);
  process.exitCode = 1;
} else {
  console.log(`INVOCK LINT: PASS\nFiles scanned: ${scanned}\nViolations: 0`);
}
