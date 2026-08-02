import { existsSync, lstatSync, realpathSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve, relative, isAbsolute } from "node:path";
import { createHmac } from "node:crypto";
import {
  type LegacySourceType,
  type LegacyArtifactFormat,
  type DiscoveredLegacyArtifact,
} from "./types.js";

export interface LegacySourceAdapter {
  readonly sourceType: LegacySourceType;
  readonly displayName: string;

  discoverRoots(): Promise<Array<{
    id: string;
    path: string;
    exists: boolean;
    sourceType: LegacySourceType;
    safeToScanByDefault: boolean;
  }>>;

  classifyArtifact(
    artifact: DiscoveredLegacyArtifact
  ): Promise<{
    recognizedDisposable: boolean;
    autoDeleteEligible: boolean;
    format: LegacyArtifactFormat;
  }>;
}

// 1.9 Path pseudonymization helper
export function getPseudonymKey(pseudonymKeyPath: string): Buffer {
  if (!existsSync(pseudonymKeyPath)) {
    // Generate a temporary fallback key if not found
    return Buffer.alloc(32, 0);
  }
  return readFileSync(pseudonymKeyPath);
}

export function computePathHmac(
  pseudonymKey: Buffer,
  sourceRootId: string,
  normalizedRelativePath: string
): string {
  return createHmac("sha256", pseudonymKey)
    .update(`legacy-path${sourceRootId}${normalizedRelativePath}`)
    .digest("hex");
}

// 1.8 Root confinement validator
export interface ConfinedPath {
  resolvedPath: string;
  normalizedRelativePath: string;
  isSymlink: boolean;
  realPath: string;
  device?: number;
  inode?: number;
}

export function verifyAndConfine(
  rootPath: string,
  targetPath: string
): ConfinedPath {
  const resolvedRoot = realpathSync(rootPath);
  let isSymlink = false;
  let currentTarget = targetPath;

  // Lstat checking
  const stats = lstatSync(targetPath);
  isSymlink = stats.isSymbolicLink();

  const realTarget = realpathSync(targetPath);
  if (!realTarget.startsWith(resolvedRoot)) {
    throw new Error("TRAVERSAL_REJECTED");
  }

  const normalizedRelativePath = relative(resolvedRoot, realTarget);

  return {
    resolvedPath: realTarget,
    normalizedRelativePath,
    isSymlink,
    realPath: realTarget,
    device: stats.dev,
    inode: stats.ino,
  };
}

export class InvockLegacyAdapter implements LegacySourceAdapter {
  readonly sourceType = "INVOCK_LEGACY" as const;
  readonly displayName = "Invock Legacy Artifacts";

  async discoverRoots() {
    const home = process.env.INVOCK_HOME ?? join(process.env.HOME ?? process.cwd(), ".invock");
    return [
      {
        id: "invock-home",
        path: home,
        exists: existsSync(home),
        sourceType: this.sourceType,
        safeToScanByDefault: true,
      },
    ];
  }

  async classifyArtifact(artifact: DiscoveredLegacyArtifact) {
    const filename = artifact.absolutePath.split("/").pop() || "";
    let format: LegacyArtifactFormat = "UNKNOWN";
    let recognizedDisposable = false;
    let autoDeleteEligible = false;

    if (filename.endsWith(".db") || filename.endsWith(".sqlite")) {
      format = "SQLITE";
    } else if (filename.endsWith("-wal")) {
      format = "SQLITE_WAL";
    } else if (filename.endsWith("-shm")) {
      format = "SQLITE_SHM";
    } else if (filename.endsWith(".json")) {
      format = "JSON";
    } else if (filename.endsWith(".jsonl")) {
      format = "JSONL";
    } else if (filename.endsWith(".log")) {
      format = "LOG";
    } else if (filename.endsWith(".txt")) {
      format = "TEXT";
    }

    // "recognized old Invock content-bearing report" or "recognized old Invock content-bearing test artifact"
    // E.g. reports ending in .report.json or containing test-artifact
    if (filename.includes("report") && format === "JSON") {
      recognizedDisposable = true;
      autoDeleteEligible = true;
    } else if (filename.includes("test-artifact") || filename.includes("test_artifact")) {
      recognizedDisposable = true;
      autoDeleteEligible = true;
    }

    return { recognizedDisposable, autoDeleteEligible, format };
  }
}

export class ClaudeLocalAdapter implements LegacySourceAdapter {
  readonly sourceType = "CLAUDE_LOCAL" as const;
  readonly displayName = "Claude Local Artifacts";

  async discoverRoots() {
    const homeDir = process.env.HOME ?? process.cwd();
    const configPath = join(homeDir, ".claude.json");
    const claudeDir = join(homeDir, ".claude");
    const anthropicDir = join(homeDir, ".anthropic");

    const roots = [];
    if (existsSync(configPath)) {
      roots.push({
        id: "claude-config",
        path: configPath,
        exists: true,
        sourceType: this.sourceType,
        safeToScanByDefault: true,
      });
    }
    if (existsSync(claudeDir)) {
      roots.push({
        id: "claude-dir",
        path: claudeDir,
        exists: true,
        sourceType: this.sourceType,
        safeToScanByDefault: true,
      });
    }
    if (existsSync(anthropicDir)) {
      roots.push({
        id: "anthropic-dir",
        path: anthropicDir,
        exists: true,
        sourceType: this.sourceType,
        safeToScanByDefault: true,
      });
    }
    return roots;
  }

  async classifyArtifact(artifact: DiscoveredLegacyArtifact) {
    const filename = artifact.absolutePath.split("/").pop() || "";
    let format: LegacyArtifactFormat = "UNKNOWN";
    if (filename.endsWith(".json")) format = "JSON";
    else if (filename.endsWith(".jsonl")) format = "JSONL";
    else if (filename.endsWith(".log")) format = "LOG";
    else if (filename.endsWith(".db") || filename.endsWith(".sqlite")) format = "SQLITE";

    const recognizedDisposable = filename.includes("history") || filename.includes("session") || filename.includes("cache") || filename.includes("log") || filename.includes("trace");
    const autoDeleteEligible = recognizedDisposable;

    return { recognizedDisposable, autoDeleteEligible, format };
  }
}

export class CodexLocalAdapter implements LegacySourceAdapter {
  readonly sourceType = "CODEX_LOCAL" as const;
  readonly displayName = "Codex Local Artifacts";

  async discoverRoots() {
    const homeDir = process.env.HOME ?? process.cwd();
    const configPath = join(homeDir, ".codex", "config.toml");
    const codexDir = join(homeDir, ".codex");

    const roots = [];
    if (existsSync(configPath)) {
      roots.push({
        id: "codex-config",
        path: configPath,
        exists: true,
        sourceType: this.sourceType,
        safeToScanByDefault: true,
      });
    }
    if (existsSync(codexDir)) {
      roots.push({
        id: "codex-dir",
        path: codexDir,
        exists: true,
        sourceType: this.sourceType,
        safeToScanByDefault: true,
      });
    }
    return roots;
  }

  async classifyArtifact(artifact: DiscoveredLegacyArtifact) {
    const filename = artifact.absolutePath.split("/").pop() || "";
    let format: LegacyArtifactFormat = "UNKNOWN";
    if (filename.endsWith(".toml") || filename.endsWith(".yaml") || filename.endsWith(".yml")) format = "YAML";
    else if (filename.endsWith(".json")) format = "JSON";
    else if (filename.endsWith(".jsonl")) format = "JSONL";
    else if (filename.endsWith(".log")) format = "LOG";
    else if (filename.endsWith(".db") || filename.endsWith(".sqlite")) format = "SQLITE";

    const recognizedDisposable = filename.includes("history") || filename.includes("session") || filename.includes("cache") || filename.includes("log") || filename.includes("trace");
    const autoDeleteEligible = recognizedDisposable;

    return { recognizedDisposable, autoDeleteEligible, format };
  }
}

export class WorkspaceAdapter implements LegacySourceAdapter {
  readonly sourceType = "WORKSPACE" as const;
  readonly displayName = "Current Workspace";

  private readonly workspaceRoot: string;

  constructor(workspaceRoot: string = process.cwd()) {
    this.workspaceRoot = workspaceRoot;
  }

  async discoverRoots() {
    return [
      {
        id: "workspace-root",
        path: this.workspaceRoot,
        exists: true,
        sourceType: this.sourceType,
        safeToScanByDefault: false, // Workspace is opt-in
      },
    ];
  }

  async classifyArtifact(artifact: DiscoveredLegacyArtifact) {
    // Workspace files should never be auto-deleted.
    const filename = artifact.absolutePath.split("/").pop() || "";
    let format: LegacyArtifactFormat = "UNKNOWN";
    if (filename.endsWith(".json")) format = "JSON";
    else if (filename.endsWith(".jsonl")) format = "JSONL";
    else if (filename.endsWith(".log")) format = "LOG";
    else if (filename.endsWith(".sqlite") || filename.endsWith(".db")) format = "SQLITE";
    else if (filename.endsWith(".env")) format = "TEXT";

    return { recognizedDisposable: false, autoDeleteEligible: false, format };
  }
}

export class CustomRootAdapter implements LegacySourceAdapter {
  readonly sourceType = "CUSTOM_ROOT" as const;
  readonly displayName = "Custom Roots";
  private readonly customPaths: string[];

  constructor(customPaths: string[] = []) {
    this.customPaths = customPaths;
  }

  async discoverRoots() {
    return this.customPaths.map((p, idx) => {
      const exists = existsSync(p);
      return {
        id: `custom-root-${idx}`,
        path: p,
        exists,
        sourceType: this.sourceType,
        safeToScanByDefault: false,
      };
    });
  }

  async classifyArtifact(artifact: DiscoveredLegacyArtifact) {
    // Custom root files are not automatically disposable by default
    const filename = artifact.absolutePath.split("/").pop() || "";
    let format: LegacyArtifactFormat = "UNKNOWN";
    if (filename.endsWith(".json")) format = "JSON";
    else if (filename.endsWith(".jsonl")) format = "JSONL";
    else if (filename.endsWith(".log")) format = "LOG";
    else if (filename.endsWith(".sqlite") || filename.endsWith(".db")) format = "SQLITE";
    else if (filename.endsWith(".env")) format = "TEXT";

    return { recognizedDisposable: false, autoDeleteEligible: false, format };
  }
}
