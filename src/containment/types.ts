export type ContainmentStatus = "completed" | "failed" | "timed_out" | "denied" | "unsupported";

export type TelemetryUnavailableReason =
  | "process_not_spawned"
  | "runtime_not_exposed"
  | "not_supported"
  | "permission_denied"
  | "process_ended_before_sample"
  | "legacy_record";

export type ResourceMeasurement<T extends number> =
  | { status: "observed"; value: T }
  | { status: "unavailable"; reason: TelemetryUnavailableReason };

export interface ContainmentTelemetry {
  pid: ResourceMeasurement<number>;
  cpuMs: ResourceMeasurement<number>;
  memoryBytes: ResourceMeasurement<number>;
}

export const MAX_TELEMETRY_PID = 2_147_483_647;
export const MAX_TELEMETRY_CPU_MS = 86_400_000;
export const MAX_TELEMETRY_MEMORY_BYTES = 16 * 1024 * 1024 * 1024;

export function unavailableTelemetry(reason: TelemetryUnavailableReason): ContainmentTelemetry {
  return {
    pid: { status: "unavailable", reason },
    cpuMs: { status: "unavailable", reason },
    memoryBytes: { status: "unavailable", reason },
  };
}

function validMeasurement(value: unknown, maximum: number): boolean {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const measurement = value as Record<string, unknown>;
  if (measurement.status === "observed") return Object.keys(measurement).length === 2 && Number.isSafeInteger(measurement.value) && (measurement.value as number) >= 0 && (measurement.value as number) <= maximum;
  return Object.keys(measurement).length === 2 && measurement.status === "unavailable" && typeof measurement.reason === "string" && ["process_not_spawned", "runtime_not_exposed", "not_supported", "permission_denied", "process_ended_before_sample", "legacy_record"].includes(measurement.reason);
}

export function isValidContainmentTelemetry(value: unknown): value is ContainmentTelemetry {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const telemetry = value as Record<string, unknown>;
  return Object.keys(telemetry).length === 3 && validMeasurement(telemetry.pid, MAX_TELEMETRY_PID) && validMeasurement(telemetry.cpuMs, MAX_TELEMETRY_CPU_MS) && validMeasurement(telemetry.memoryBytes, MAX_TELEMETRY_MEMORY_BYTES);
}

export interface ContainmentMount {
  source: string;
  target: string;
  readOnly?: boolean;
}

export interface ContainmentProfile {
  fixtureRoot: string;
  allowedCommands: string[];
  timeoutMs?: number;
  maxOutputBytes?: number;
  maxArgvBytes?: number;
  sandbox?: "required" | "none";
  network?: "none" | "experimental-allowlist";
  readOnlyRoot?: boolean;
  nonRoot?: boolean;
  noNewPrivileges?: boolean;
  maxPids?: number;
  memoryLimitMb?: number;
  cpuSeconds?: number;
  image?: string;
  imageDigest?: string;
  mounts?: ContainmentMount[];
}

export interface ContainmentRequest {
  profile: ContainmentProfile;
  command: string;
  argv?: string[];
  env?: Record<string, string>;
}

export interface ContainmentResult {
  status: ContainmentStatus;
  stdout: string;
  stderr: string;
  exitCode?: number;
  signal?: string;
  durationMs: number;
  reasonCodes: string[];
  cleanup?: "completed" | "failed" | "not_run";
  /** Host/runtime measurements are present for new records; legacy records are normalized to unavailable states when signed/exported. */
  telemetry?: ContainmentTelemetry;
  capabilities: {
    sandbox: "available" | "unavailable" | "not_requested";
    network: "denied" | "unknown";
    readOnlyRoot: boolean;
    nonRoot: boolean;
    noNewPrivileges: boolean;
  };
}
