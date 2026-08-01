import type { CommandAnalysis } from "./types.js";

/** Maximum input size accepted by the analyzer (1 MiB). Larger inputs are flagged. */
export const MAX_COMMAND_LENGTH = 1024 * 1024;

const NETWORK_EXECUTABLES = new Set([
  "curl", "wget", "nc", "netcat", "ssh", "scp", "sftp", "ftp", "telnet", "ncat", "socat",
]);

const SHELL_EXECUTABLES = new Set(["sh", "bash", "zsh", "ksh", "dash", "fish", "csh", "tcsh", "pwsh", "powershell", "cmd", "cmd.exe"]);

const DESTRUCTIVE_EXECUTABLES = new Set(["shred", "mkfs", "fdisk", "format", "dd"]);

const PRIVILEGE_EXECUTABLES = new Set(["sudo", "su", "pkexec", "doas", "runas"]);

const WRITE_EXECUTABLES = new Set(["tee", "touch", "mkdir", "mv", "cp", "install", "ln"]);

const DELETE_EXECUTABLES = new Set(["rm", "unlink", "rmdir"]);

const SHELL_META = ["|", ";", "&", "$", "`", ">", "<", "*", "?", "(", ")", "&&", "||"];

const OPAQUE_SHELL_PATTERNS: Array<{ re: RegExp; code: string; message: string }> = [
  { re: /(^|[;&|]\s*)(curl|wget)\b[^;&|]*\|\s*(sh|bash|zsh)\b/iu, code: "PIPE_TO_SHELL", message: "downloaded content piped directly into a shell" },
  { re: /(^|[;&|]\s*)(sh|bash|zsh)\b[^;&|]*\|\s*(sh|bash|zsh)\b/iu, code: "SHELL_PIPE_TO_SHELL", message: "shell output piped into another shell" },
];

function basenameOf(executable: string): string {
  const normalized = executable.replaceAll("\\", "/");
  const base = normalized.split("/").pop() ?? normalized;
  return base.toLowerCase();
}

function isTrivialPath(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed === "" || trimmed === "." || trimmed === "..") return true;
  if (trimmed === "/" || trimmed === "~") return true;
  if (/^~\/?$/u.test(trimmed)) return true;
  return false;
}

function isRootPath(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed === "/") return true;
  if (/^\/[^/]*$/u.test(trimmed)) return true;
  if (/^[a-zA-Z]:[\\/]?$/u.test(trimmed)) return true;
  return false;
}

function isSetuidMode(value: string): boolean {
  const mode = value.trim();
  if (!/^[0-7]{3,4}$/u.test(mode)) return false;
  const digits = mode.length === 4 ? mode : `0${mode}`;
  const special = digits[0];
  return special === "4" || special === "6" || special === "7";
}

function isChownToRoot(argv: string[], index: number): boolean {
  for (let j = index + 1; j < argv.length; j++) {
    const arg = argv[j]!;
    if (arg === "--") continue;
    if (arg.startsWith("-")) continue;
    const owner = arg.split(":")[0]?.toLowerCase();
    if (owner === "root" || owner === "0") return true;
    break;
  }
  return false;
}

function hasRedirection(argv: string[]): boolean {
  return argv.some(arg => arg === ">" || arg === ">>" || arg.startsWith(">") || arg.startsWith(">>"));
}

function hasShellMeta(argv: string[]): boolean {
  return argv.some(arg => SHELL_META.some(meta => arg.includes(meta)));
}

function hasCommandSubstitution(argv: string[]): boolean {
  return argv.some(arg => arg.includes("$(") || arg.includes("`"));
}

function hasPipeToShell(argv: string[]): boolean {
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === undefined) continue;
    if (arg === "|" || arg === "|&") {
      const next = argv[i + 1];
      if (next !== undefined && SHELL_EXECUTABLES.has(basenameOf(next))) return true;
    }
  }
  return false;
}

function hasPythonNetwork(argv: string[]): boolean {
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === undefined) continue;
    if (arg === "-c" || arg === "-c " || arg === "-c'") {
      const code = argv[i + 1];
      if (code !== undefined && /(socket|requests|urllib|http\.client|ftplib|smtplib|paramiko|subprocess)/iu.test(code)) return true;
    }
  }
  return false;
}

function hasBashCurlPipe(argv: string[]): boolean {
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === undefined) continue;
    if (arg === "-c" || arg === "-c " || arg === "-c'") {
      const code = argv[i + 1];
      if (code !== undefined && OPAQUE_SHELL_PATTERNS.some(pattern => pattern.re.test(code))) return true;
    }
  }
  return false;
}

function analyzeArgv(argv: string[]): CommandAnalysis {
  const dangerous: Array<{ code: string; message: string }> = [];
  const riskSignals: string[] = [];
  let networkAccess = false;
  let filesystemWrite = false;
  let filesystemDelete = false;
  let privilegeEscalation = false;

  const executable = argv[0] ?? "";
  const base = basenameOf(executable);

  if (NETWORK_EXECUTABLES.has(base)) {
    networkAccess = true;
    dangerous.push({ code: "NETWORK_EXECUTABLE", message: `${base} performs network access` });
  }
  if (SHELL_EXECUTABLES.has(base)) {
    riskSignals.push("SHELL_INTERPRETER");
  }
  if (PRIVILEGE_EXECUTABLES.has(base)) {
    privilegeEscalation = true;
    dangerous.push({ code: "PRIVILEGE_ESCALATION", message: `${base} elevates privileges` });
  }
  if (DESTRUCTIVE_EXECUTABLES.has(base)) {
    filesystemDelete = true;
    dangerous.push({ code: "DESTRUCTIVE_COMMAND", message: `${base} is a destructive command` });
  }
  if (WRITE_EXECUTABLES.has(base)) {
    filesystemWrite = true;
  }
  if (DELETE_EXECUTABLES.has(base)) {
    filesystemDelete = true;
  }

  if (base === "rm") {
    let recursive = false;
    let force = false;
    let target: string | undefined;
    for (let i = 1; i < argv.length; i++) {
      const arg = argv[i]!;
      if (arg === "--") {
        target = argv[i + 1];
        break;
      }
      if (arg.startsWith("-") && arg !== "-") {
        if (arg.includes("r") || arg.includes("R")) recursive = true;
        if (arg.includes("f")) force = true;
        continue;
      }
      target = arg;
      break;
    }
    if (recursive || force) {
      if (target === undefined || isTrivialPath(target)) {
        dangerous.push({ code: "RM_RECURSIVE_FORCE", message: "rm -r/-f targets a trivial or unspecified path" });
      } else {
        dangerous.push({ code: "RM_RECURSIVE_FORCE", message: `rm -r/-f targets ${target}` });
      }
    }
  }

  if (base === "dd") {
    const hasOf = argv.some(arg => arg === "of=" || arg.startsWith("of="));
    if (hasOf) {
      filesystemWrite = true;
      dangerous.push({ code: "DD_WRITE", message: "dd writes directly to a device or file via of=" });
    }
  }

  if (base === "chmod") {
    for (let i = 1; i < argv.length; i++) {
      const arg = argv[i]!;
      if (arg.startsWith("-")) continue;
      if (isSetuidMode(arg)) {
        privilegeEscalation = true;
        dangerous.push({ code: "SETUID_CHMOD", message: `chmod ${arg} sets setuid/setgid bits` });
      }
      break;
    }
  }

  if (base === "chown" && isChownToRoot(argv, 0)) {
    privilegeEscalation = true;
    dangerous.push({ code: "CHOWN_TO_ROOT", message: "chown transfers ownership to root" });
  }

  if (base === "python" || base === "python3" || base === "python2" || base === "node" || base === "perl" || base === "ruby") {
    if (hasPythonNetwork(argv)) {
      networkAccess = true;
      dangerous.push({ code: "SCRIPT_NETWORK", message: `${base} -c embeds network-capable code` });
    }
  }

  if (base === "bash" || base === "sh" || base === "zsh" || base === "ksh" || base === "dash") {
    if (hasBashCurlPipe(argv)) {
      networkAccess = true;
      dangerous.push({ code: "PIPE_TO_SHELL", message: "downloaded content piped directly into a shell" });
    }
  }

  if (hasPipeToShell(argv)) {
    riskSignals.push("PIPE_TO_SHELL");
  }
  if (hasCommandSubstitution(argv)) {
    riskSignals.push("COMMAND_SUBSTITUTION");
  }
  if (hasRedirection(argv)) {
    filesystemWrite = true;
    riskSignals.push("REDIRECTION");
  }
  if (hasShellMeta(argv)) {
    riskSignals.push("SHELL_METACHARACTERS");
  }

  return {
    executable,
    argv: [...argv],
    dangerous,
    riskSignals: [...new Set(riskSignals)],
    networkAccess,
    filesystemWrite,
    filesystemDelete,
    privilegeEscalation,
  };
}

/** Split a shell string on whitespace, respecting single/double quotes and backslash escapes. */
function tokenizeShellString(shell: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let quote: "'" | '"' | undefined;
  let escaped = false;
  for (const ch of shell) {
    if (escaped) {
      current += ch;
      escaped = false;
      continue;
    }
    if (ch === "\\") {
      escaped = true;
      continue;
    }
    if (quote !== undefined) {
      if (ch === quote) quote = undefined;
      else current += ch;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      continue;
    }
    if (ch === " " || ch === "\t" || ch === "\n" || ch === "\r") {
      if (current !== "") {
        tokens.push(current);
        current = "";
      }
      continue;
    }
    current += ch;
  }
  if (escaped) current += "\\";
  if (current !== "") tokens.push(current);
  return tokens;
}

/**
 * Analyze a command expressed as an argv array.
 *
 * Deterministic and bounded: inputs larger than MAX_COMMAND_LENGTH are flagged
 * with SIZE_LIMIT_EXCEEDED. Never throws.
 */
export function analyzeCommand(argv: string[]): CommandAnalysis {
  try {
    const total = argv.reduce((sum, arg) => sum + arg.length, 0);
    if (total > MAX_COMMAND_LENGTH) {
      return {
        executable: argv[0] ?? "",
        argv: [...argv],
        dangerous: [],
        riskSignals: ["SIZE_LIMIT_EXCEEDED"],
        networkAccess: false,
        filesystemWrite: false,
        filesystemDelete: false,
        privilegeEscalation: false,
      };
    }
    return analyzeArgv(argv);
  } catch {
    return {
      executable: argv[0] ?? "",
      argv: [...argv],
      dangerous: [],
      riskSignals: ["ANALYSIS_FAILED"],
      networkAccess: false,
      filesystemWrite: false,
      filesystemDelete: false,
      privilegeEscalation: false,
    };
  }
}

/**
 * Analyze an opaque shell string. The string is tokenized conservatively
 * (whitespace split respecting quotes) and analyzed like an argv array, with
 * OPAQUE_SHELL flagged as a risk signal.
 *
 * Deterministic and bounded. Never throws.
 */
export function analyzeShellString(shell: string): CommandAnalysis {
  try {
    if (shell.length > MAX_COMMAND_LENGTH) {
      return {
        executable: "",
        argv: [],
        dangerous: [],
        riskSignals: ["SIZE_LIMIT_EXCEEDED"],
        networkAccess: false,
        filesystemWrite: false,
        filesystemDelete: false,
        privilegeEscalation: false,
      };
    }
    const argv = tokenizeShellString(shell);
    const analysis = analyzeArgv(argv);
    analysis.riskSignals.push("OPAQUE_SHELL");
    analysis.riskSignals = [...new Set(analysis.riskSignals)];
    return analysis;
  } catch {
    return {
      executable: "",
      argv: [],
      dangerous: [],
      riskSignals: ["OPAQUE_SHELL", "ANALYSIS_FAILED"],
      networkAccess: false,
      filesystemWrite: false,
      filesystemDelete: false,
      privilegeEscalation: false,
    };
  }
}
