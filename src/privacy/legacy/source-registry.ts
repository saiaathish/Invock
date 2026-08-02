import {
  InvockLegacyAdapter,
  ClaudeLocalAdapter,
  CodexLocalAdapter,
  WorkspaceAdapter,
  CustomRootAdapter,
  type LegacySourceAdapter,
} from "./sources.js";
import { type LegacySourceType } from "./types.js";

export class LegacySourceRegistry {
  private readonly adapters = new Map<LegacySourceType, LegacySourceAdapter>();

  constructor(workspaceRoot?: string, customPaths?: string[]) {
    this.register(new InvockLegacyAdapter());
    this.register(new ClaudeLocalAdapter());
    this.register(new CodexLocalAdapter());
    this.register(new WorkspaceAdapter(workspaceRoot));
    this.register(new CustomRootAdapter(customPaths));
  }

  public register(adapter: LegacySourceAdapter): void {
    this.adapters.set(adapter.sourceType, adapter);
  }

  public getAdapter(type: LegacySourceType): LegacySourceAdapter | undefined {
    return this.adapters.get(type);
  }

  public getAdapters(): LegacySourceAdapter[] {
    return Array.from(this.adapters.values());
  }
}
