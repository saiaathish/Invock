const fs = await import("node:fs");

let hostRead = false;
try {
  fs.readFileSync(process.env.INVOCK_HOST_READ_PROBE ?? "/etc/passwd", "utf8");
  hostRead = true;
} catch {}

let writeDenied = false;
try {
  fs.writeFileSync(process.env.INVOCK_WRITE_TARGET ?? "/tmp/invock-containment-write", "blocked");
} catch {
  writeDenied = true;
}

let networkDenied = false;
const net = await import("node:net");
await new Promise((resolve) => {
  const socket = net.createConnection({ host: "127.0.0.1", port: 9 });
  const timer = setTimeout(() => { socket.destroy(); networkDenied = true; resolve(); }, 500);
  socket.once("connect", () => { clearTimeout(timer); socket.destroy(); resolve(); });
  socket.once("error", () => { clearTimeout(timer); networkDenied = true; resolve(); });
});

process.stdout.write(JSON.stringify({ hostRead, writeDenied, networkDenied }) + "\n");
