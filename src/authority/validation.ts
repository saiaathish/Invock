import type { Capability, Effect } from "../core/types.js";
import { digestJson, stableUnique } from "../core/canonical.js";
import type { AuthorityBudgets, AuthorityDataConstraints, AuthorityResourceConstraints } from "./types.js";

const capabilities = new Set<Capability>(["fs.read", "fs.write", "fs.delete", "net.read", "net.send", "process.execute", "process.shell", "message.send", "secret.read", "unknown"]);
const effects = new Set<Effect>(["data.observe", "data.modify", "data.delete", "external.read", "external.disclosure", "external.communication", "process.spawn", "command.interpretation", "persistent.change", "irreversible.action", "unknown"]);

export function object(value: unknown, name: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${name} must be an object`);
  return value as Record<string, unknown>;
}

export function strings(value: unknown, name: string): string[] {
  if (!Array.isArray(value) || value.some(item => typeof item !== "string" || item.length === 0)) throw new Error(`${name} must be a non-empty string array`);
  return stableUnique(value);
}

export function enumStrings<T extends string>(value: unknown, name: string, allowed: Set<T>): T[] {
  const result = strings(value, name);
  if (result.some(item => !allowed.has(item as T))) throw new Error(`${name} contains an unsupported value`);
  return result as T[];
}

export function iso(value: unknown, name: string): string {
  if (typeof value !== "string" || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$/.test(value) || !Number.isFinite(Date.parse(value))) throw new Error(`${name} must be an ISO UTC timestamp`);
  return value;
}

export function future(expiresAt: string, now: Date): void {
  if (Date.parse(expiresAt) <= now.getTime()) throw new Error("Authority has already expired");
}

export function constraints(value: unknown, name: string): { resources: AuthorityResourceConstraints; data: AuthorityDataConstraints } {
  const source = object(value, name);
  const resource = object(source.resources, `${name}.resources`);
  const data = object(source.data, `${name}.data`);
  return {
    resources: { paths: strings(resource.paths, `${name}.resources.paths`), domains: strings(resource.domains, `${name}.resources.domains`), recipients: strings(resource.recipients, `${name}.resources.recipients`) },
    data: { allowedLabels: strings(data.allowedLabels, `${name}.data.allowedLabels`), forbiddenLabels: strings(data.forbiddenLabels, `${name}.data.forbiddenLabels`) },
  };
}

export function budgets(value: unknown): AuthorityBudgets {
  const source = object(value, "budgets");
  const output: AuthorityBudgets = {};
  for (const key of ["calls", "bytes", "durationSeconds"] as const) {
    const item = source[key];
    if (item !== undefined && (!Number.isSafeInteger(item) || (item as number) < 0)) throw new Error(`budgets.${key} must be a non-negative safe integer`);
    if (item !== undefined) output[key] = item as number;
  }
  return output;
}

export function digestWithoutDigest<T extends Record<string, unknown>>(value: T): string { return digestJson(value); }
export { capabilities, effects };
