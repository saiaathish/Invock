import { lookup } from "node:dns/promises";

export interface PinnedAddressSet { addresses: string[]; }

/** Resolves one hostname once so callers can connect to the pinned address. */
export async function pinDns(hostname: string): Promise<PinnedAddressSet> {
  if (!/^[A-Za-z0-9.-]+$/.test(hostname) || hostname.length > 253) throw new Error("DNS_HOST_INVALID");
  const records = await lookup(hostname, { all: true, verbatim: true });
  const addresses = [...new Set(records.map(record => record.address))].sort();
  if (addresses.length === 0) throw new Error("DNS_PIN_EMPTY");
  return { addresses };
}

export interface RedirectGuard { maxRedirects: number; allowCrossHost: boolean; allowedHosts?: readonly string[]; }

/** Validates a redirect target without performing I/O. */
export function guardRedirect(current: URL, location: string, policy: RedirectGuard, count: number): URL {
  if (!Number.isInteger(count) || count > policy.maxRedirects) throw new Error("REDIRECT_LIMIT_EXCEEDED");
  const next = new URL(location, current);
  if (next.protocol !== "http:" && next.protocol !== "https:") throw new Error("REDIRECT_PROTOCOL_DENIED");
  if (next.hostname !== current.hostname && !policy.allowCrossHost) throw new Error("REDIRECT_CROSS_HOST_DENIED");
  if (policy.allowedHosts !== undefined && !policy.allowedHosts.includes(next.hostname)) throw new Error("REDIRECT_HOST_NOT_ALLOWED");
  return next;
}
