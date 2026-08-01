import assert from "node:assert/strict";
import { test } from "node:test";
import { guardRedirect } from "../src/net/index.js";

test("redirect guard permits same-host redirects and blocks cross-host targets", () => {
  const current = new URL("http://127.0.0.1:1234/mcp");
  assert.equal(guardRedirect(current, "/next", { maxRedirects: 2, allowCrossHost: false }, 0).pathname, "/next");
  assert.throws(() => guardRedirect(current, "http://attacker.test/mcp", { maxRedirects: 2, allowCrossHost: false }, 0), /REDIRECT_CROSS_HOST_DENIED/);
});

test("redirect guard enforces count, host allow-list, and protocol", () => {
  const current = new URL("https://service.test/mcp");
  assert.throws(() => guardRedirect(current, "/next", { maxRedirects: 1, allowCrossHost: false }, 2), /REDIRECT_LIMIT_EXCEEDED/);
  assert.throws(() => guardRedirect(current, "https://other.test/mcp", { maxRedirects: 2, allowCrossHost: true, allowedHosts: ["service.test"] }, 0), /REDIRECT_HOST_NOT_ALLOWED/);
  assert.throws(() => guardRedirect(current, "file:///tmp/x", { maxRedirects: 2, allowCrossHost: true }, 0), /REDIRECT_PROTOCOL_DENIED/);
});
