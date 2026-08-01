/**
 * Explicitly implemented MCP protocol profiles. Keep this registry closed:
 * negotiation must never silently opt into an unknown protocol version.
 */
export interface ProtocolProfile {
  readonly version: string;
  readonly generation: "stable-2025" | "candidate-2026";
  readonly stateModel: "session" | "request";
  readonly supportedTransports: readonly ("stdio" | "streamable-http")[];
}

export interface NegotiationRequest {
  readonly clientVersions: readonly string[];
  readonly serverVersions?: readonly string[];
  readonly requestedVersion?: string;
}

export interface NegotiationResult {
  readonly ok: boolean;
  readonly profile?: ProtocolProfile;
  readonly reason?: "NO_COMMON_PROFILE" | "UNKNOWN_VERSION" | "AMBIGUOUS_DOWNGRADE" | "INVALID_REQUEST";
  readonly supportedVersions: readonly string[];
}

const PROFILES: readonly ProtocolProfile[] = Object.freeze([
  Object.freeze({ version: "2026-07-28", generation: "candidate-2026", stateModel: "request", supportedTransports: Object.freeze(["stdio", "streamable-http"] as const) }),
  Object.freeze({ version: "2025-11-25", generation: "stable-2025", stateModel: "session", supportedTransports: Object.freeze(["stdio", "streamable-http"] as const) }),
  Object.freeze({ version: "2025-06-18", generation: "stable-2025", stateModel: "session", supportedTransports: Object.freeze(["stdio", "streamable-http"] as const) }),
  Object.freeze({ version: "2025-03-26", generation: "stable-2025", stateModel: "session", supportedTransports: Object.freeze(["stdio", "streamable-http"] as const) }),
]);

const PROFILE_BY_VERSION = new Map(PROFILES.map(profile => [profile.version, profile]));
const SUPPORTED_VERSIONS: readonly string[] = Object.freeze(PROFILES.map(profile => profile.version));

function uniqueVersions(versions: readonly string[]): boolean {
  return new Set(versions).size === versions.length;
}

/** Negotiate only a profile present in the closed, deterministic registry. */
export function negotiateProfile(request: NegotiationRequest): NegotiationResult {
  if (!Array.isArray(request.clientVersions) || request.clientVersions.length === 0 || !uniqueVersions(request.clientVersions)) {
    return { ok: false, reason: "INVALID_REQUEST", supportedVersions: SUPPORTED_VERSIONS };
  }
  const serverVersions = request.serverVersions ?? SUPPORTED_VERSIONS;
  if (!Array.isArray(serverVersions) || serverVersions.length === 0 || !uniqueVersions(serverVersions)) {
    return { ok: false, reason: "INVALID_REQUEST", supportedVersions: SUPPORTED_VERSIONS };
  }
  if (request.requestedVersion !== undefined && !PROFILE_BY_VERSION.has(request.requestedVersion)) {
    return { ok: false, reason: "UNKNOWN_VERSION", supportedVersions: SUPPORTED_VERSIONS };
  }
  const unknownClient = request.clientVersions.some(version => !PROFILE_BY_VERSION.has(version));
  const unknownServer = serverVersions.some(version => !PROFILE_BY_VERSION.has(version));
  if (unknownClient || unknownServer) return { ok: false, reason: "UNKNOWN_VERSION", supportedVersions: SUPPORTED_VERSIONS };

  if (request.requestedVersion !== undefined) {
    const profile = PROFILE_BY_VERSION.get(request.requestedVersion);
    if (!profile || !request.clientVersions.includes(request.requestedVersion) || !serverVersions.includes(request.requestedVersion)) {
      return { ok: false, reason: "NO_COMMON_PROFILE", supportedVersions: SUPPORTED_VERSIONS };
    }
    return { ok: true, profile, supportedVersions: SUPPORTED_VERSIONS };
  }

  const common = SUPPORTED_VERSIONS.filter(version => request.clientVersions.includes(version) && serverVersions.includes(version));
  if (common.length === 0) return { ok: false, reason: "NO_COMMON_PROFILE", supportedVersions: SUPPORTED_VERSIONS };
  if (common.length > 1) return { ok: false, reason: "AMBIGUOUS_DOWNGRADE", supportedVersions: SUPPORTED_VERSIONS };
  const selectedVersion = common[0];
  if (selectedVersion === undefined) return { ok: false, reason: "NO_COMMON_PROFILE", supportedVersions: SUPPORTED_VERSIONS };
  const profile = PROFILE_BY_VERSION.get(selectedVersion);
  if (!profile) return { ok: false, reason: "NO_COMMON_PROFILE", supportedVersions: SUPPORTED_VERSIONS };
  return { ok: true, profile, supportedVersions: SUPPORTED_VERSIONS };
}

export function implementedProfiles(): readonly ProtocolProfile[] {
  return PROFILES;
}
