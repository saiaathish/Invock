import { execFileSync } from "node:child_process";

function run(command: string, args: string[]): string {
  return execFileSync(command, args, { encoding: "utf8", timeout: 180_000, stdio: ["ignore", "pipe", "pipe"] });
}

run("pnpm", ["test"]);
run("pnpm", ["typecheck"]);
run("pnpm", ["build"]);
const certifyA = run("pnpm", ["certify"]);
const certifyB = run("pnpm", ["certify"]);
if (certifyA !== certifyB) throw new Error("BASE_CERTIFICATION_NONDETERMINISTIC");
const dockerA = run("pnpm", ["docker-containment-test"]);
const dockerB = run("pnpm", ["docker-containment-test"]);
if (!dockerA.includes('"status":"pass"') || !dockerB.includes('"status":"pass"')) throw new Error("DOCKER_CONTAINMENT_NOT_PROVEN");
if (dockerA !== dockerB) throw new Error("DOCKER_CERTIFICATION_NONDETERMINISTIC");
run("pnpm", ["arena"]);
run("pnpm", ["mutation-review"]);
console.log("INVOCK EXPANDED CERTIFICATION: PASS\nFull suite, build, deterministic double certification, Docker attack probe, Arena, and mutation review passed twice where applicable.");
