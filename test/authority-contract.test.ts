import test from "node:test";
import assert from "node:assert/strict";
import { effectiveAuthorityDigest, type EffectiveAuthority } from "../src/core/authority.js";
test("effective authority digest is deterministic", () => { const a: EffectiveAuthority = { staticPolicyDigest: "p", toolSchemaDigest: "t", registryVersion: "1", constraints: { tools: { allow: ["x"], deny: [] }, capabilities: { allow: [], deny: [] }, effects: { allow: [], deny: [] }, resources: { paths: [], domains: [], recipients: [] }, data: { allowedLabels: [], forbiddenLabels: [] }, budgets: {}, temporal: {} } }; assert.equal(effectiveAuthorityDigest(a), effectiveAuthorityDigest(structuredClone(a))); });
