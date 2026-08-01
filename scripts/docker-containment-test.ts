import { spawnSync } from "node:child_process";

const probe = spawnSync("docker", ["version", "--format", "{{.Server.Version}}"], { encoding: "utf8" });
if (probe.status !== 0) {
  console.log(JSON.stringify({ status: "unsupported", reason: "DOCKER_RUNTIME_UNAVAILABLE" }));
  process.exitCode = 2;
} else {
  const build = spawnSync("docker", ["build", "--tag", "invock-containment:local", "--file", "docker/containment.Dockerfile", "."], { encoding: "utf8" });
  if (build.status !== 0) {
    console.log(JSON.stringify({ status: "fail", reason: "DOCKER_IMAGE_BUILD_FAILED", stdout: build.stdout, stderr: build.stderr }));
    process.exitCode = 1;
    process.exit();
  }
  const attack = "const fs=require('node:fs'); let writeDenied=false; try{fs.writeFileSync('/etc/invock-attack','x')}catch{writeDenied=true} const controller=new AbortController(); setTimeout(()=>controller.abort(),300); fetch('http://example.com',{signal:controller.signal}).then(()=>process.exit(1)).catch(()=>process.exit(writeDenied?0:1));";
  const result = spawnSync("docker", ["run", "--rm", "--network", "none", "--read-only", "--memory", "64m", "--cpus", "0.5", "--pids-limit", "64", "--cap-drop=ALL", "--security-opt", "no-new-privileges", "invock-containment:local", "-e", attack], { encoding: "utf8", timeout: 10_000 });
  const passed = result.status === 0;
  console.log(JSON.stringify({ status: passed ? "pass" : "fail", exitCode: result.status, stdout: result.stdout, stderr: result.stderr }));
  if (!passed) process.exitCode = 1;
}
