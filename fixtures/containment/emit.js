const mode = process.argv[2] ?? "ok";
if (mode === "sleep") await new Promise(resolve => setTimeout(resolve, Number(process.argv[3] ?? 10_000)));
else if (mode === "output") process.stdout.write("x".repeat(Number(process.argv[3] ?? 100_000)));
else if (mode === "network") { await fetch("https://example.com"); }
else if (mode === "child") { const child = (await import("node:child_process")).spawn(process.execPath, ["-e", "setTimeout(() => {}, 100000)"], { detached: false }); await new Promise(resolve => child.once("spawn", resolve)); }
else process.stdout.write("ok\n");
