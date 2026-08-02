import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { generateSupplyChainSigningMaterial, scanSupplyChain, verifySupplyChainSignature } from "../src/supplychain/index.js";

test("supply-chain inventory is deterministic and evidence-only", () => {
  const root = mkdtempSync(join(tmpdir(), "invock-supply-chain-"));
  try {
    writeFileSync(join(root, "package.json"), JSON.stringify({ name: "fixture", version: "1.0.0", dependencies: { alpha: "^1.2.3" }, devDependencies: { beta: "~2.0.0" } }));
    writeFileSync(join(root, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\npackages:\n  alpha@1.2.3:\n    resolution: {integrity: sha512-alpha}\n  beta@2.0.0:\n    resolution: {integrity: sha512-beta}\n");
    writeFileSync(join(root, "Dockerfile"), "FROM example/image:latest\n");
    mkdirSync(join(root, "docker"), { recursive: true });
    writeFileSync(join(root, "docker", "containment.Dockerfile"), "FROM example/containment@sha256:" + "a".repeat(64) + "\n");
    const first = scanSupplyChain(root);
    const second = scanSupplyChain(root);
    assert.equal(first.reproducibleDigest, second.reproducibleDigest);
    assert.equal(first.lockfileStatus, "present");
    assert.equal(first.resolutionStatus, "resolved");
    assert.equal(first.advisoryStatus, "not-queried");
    assert.equal(first.signatureStatus, "not-verified");
    assert.equal(first.claims.maliciousPackage, "not-claimed");
    assert.equal(first.claims.provenance, "evidence-only");
    assert.deepEqual(first.dependencies.map(item => item.name), ["alpha", "beta"]);
    assert.deepEqual(first.resolvedDependencies.map(item => item.name), ["alpha", "beta"]);
    assert.equal(first.sbom.components.length, 3);
    assert.match(first.sbom.serialNumber, /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
    assert.equal(first.containerReferences[0]?.digestPinned, true);
    assert.equal(first.containerReferences[1]?.digestPinned, false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("supply-chain scan refuses to call an unreadable lockfile a resolved SBOM", () => {
  const root = mkdtempSync(join(tmpdir(), "invock-supply-chain-unresolved-"));
  try {
    writeFileSync(join(root, "package.json"), JSON.stringify({ name: "fixture", version: "1.0.0", dependencies: { alpha: "^1.2.3" } }));
    writeFileSync(join(root, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    const report = scanSupplyChain(root);
    assert.equal(report.lockfileStatus, "present");
    assert.equal(report.resolutionStatus, "unresolved");
    assert.equal(report.resolutionCompleteness, "none");
    assert.deepEqual(report.resolvedDependencies, []);
    assert.equal(report.sbom.components[1]?.scope, "runtime:unresolved-lockfile");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("supply-chain marks package-only resolution partial when importer edges are absent", () => {
  const root = mkdtempSync(join(tmpdir(), "invock-supply-chain-no-importers-"));
  try {
    writeFileSync(join(root, "package.json"), JSON.stringify({ name: "fixture", dependencies: { alpha: "1.2.3" } }));
    writeFileSync(join(root, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\npackages:\n  alpha@1.2.3:\n    resolution: {integrity: sha512-alpha}\n");
    const report = scanSupplyChain(root);
    assert.equal(report.resolutionStatus, "resolved");
    assert.equal(report.resolutionCompleteness, "partial");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("supply-chain preserves importer edges and marks incomplete resolution partial", () => {
  const root = mkdtempSync(join(tmpdir(), "invock-supply-chain-edges-"));
  try {
    writeFileSync(join(root, "package.json"), JSON.stringify({ name: "fixture", dependencies: { alpha: "^1.0.0" } }));
    writeFileSync(join(root, "pnpm-lock.yaml"), `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      alpha: { specifier: ^1.0.0, version: 1.2.3 }
      missing: { specifier: ^2.0.0 }
packages:
  alpha@1.2.3:
    resolution: {integrity: sha512-alpha}
snapshots:
  alpha@1.2.3:
    dependencies: { transitive: 3.0.0 }
`);
    const report = scanSupplyChain(root);
    assert.equal(report.resolutionCompleteness, "partial");
    assert.equal(report.importerSnapshots[0]?.dependencies.missing?.resolvedVersion, undefined);
    assert.ok(report.dependencyEdges.some(edge => edge.name === "transitive" && edge.resolved));
    assert.equal(report.lockfileMetadata.format, "pnpm");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("advisory status requires evidence and is covered by mutation-resistant signing", () => {
  const root = mkdtempSync(join(tmpdir(), "invock-supply-chain-advisory-"));
  try {
    writeFileSync(join(root, "package.json"), JSON.stringify({ name: "fixture" }));
    const evidenceDigest = "a".repeat(43);
    const report = scanSupplyChain(root, { advisory: { status: "queried-no-findings", evidenceDigest } });
    assert.equal(report.advisoryStatus, "queried-no-findings");
    assert.equal(report.advisoryEvidenceDigest, evidenceDigest);
    assert.throws(() => scanSupplyChain(root, { advisory: { status: "queried-findings", evidenceDigest: "bad" } }), /SUPPLY_CHAIN_ADVISORY_EVIDENCE_REQUIRED/);
    const signed = scanSupplyChain(root, { signing: generateSupplyChainSigningMaterial(), advisory: { status: "queried-no-findings", evidenceDigest } });
    assert.equal(verifySupplyChainSignature({ ...signed, resolutionCompleteness: "partial" }), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("supply-chain signing covers the report and rejects tampering", () => {
  const root = mkdtempSync(join(tmpdir(), "invock-supply-chain-signed-"));
  try {
    writeFileSync(join(root, "package.json"), JSON.stringify({ name: "fixture", version: "1.0.0", dependencies: { alpha: "1.2.3" } }));
    writeFileSync(join(root, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\npackages:\n  alpha@1.2.3:\n    resolution: {integrity: sha512-alpha}\n");
    const signed = scanSupplyChain(root, { signing: generateSupplyChainSigningMaterial() });
    assert.equal(signed.signatureStatus, "verified");
    assert.equal(signed.claims.provenance, "signed-local-evidence");
    assert.ok(signed.signature);
    assert.equal(verifySupplyChainSignature(signed), true);
    assert.equal(verifySupplyChainSignature({ ...signed, dependencies: [...signed.dependencies, { name: "tampered", requestedVersion: "1.0.0", scope: "runtime" }] }), false);
    assert.equal(verifySupplyChainSignature({ ...signed, signatureStatus: "not-verified" }), false);
    assert.equal(verifySupplyChainSignature({ ...signed, claims: { ...signed.claims, provenance: "evidence-only" } }), false);
    assert.equal(verifySupplyChainSignature(signed, signed.signature, "-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----\n"), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
