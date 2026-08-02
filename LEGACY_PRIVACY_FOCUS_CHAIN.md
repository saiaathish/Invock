# Invock Legacy Privacy Focus Chain

## Stage 1 — Contracts and Source Discovery

- [x] Legacy source types exist
- [x] Finding categories exist
- [x] Remediation actions exist
- [x] Provider-history states exist
- [x] Protection-boundary states exist
- [x] In-memory artifact type exists
- [x] Persistent content-free finding type exists
- [x] Content-free remediation plan exists
- [x] Claude source discovery exists
- [x] Codex source discovery exists
- [x] Invock legacy-source discovery exists
- [x] Custom-root discovery exists
- [x] Symlink-safe root confinement exists
- [x] Stage 1 tests pass
- [x] Existing full suite remains green

## Stage 2 — Local Scanner

- [x] Scanning requires explicit consent
- [x] Default scan avoids entire home directory
- [x] Scanner uses no remote model
- [x] Scanner uses no external network
- [x] Text detector exists
- [x] Secret detector exists
- [x] PII detector exists
- [x] Conversation-history detector exists
- [x] SQLite detector exists
- [x] JSON and JSONL detector exists
- [x] Log detector exists
- [x] Opaque archive handling exists
- [x] File-size bounds exist
- [x] Binary-file bounds exist
- [x] Symlink escapes are blocked
- [x] Findings contain no snippets
- [x] Findings contain no raw secrets
- [x] Persistent reports contain no raw paths
- [x] Scan cancellation cleans memory
- [x] Scan failure cleans memory
- [x] Stage 2 tests pass
- [x] Existing full suite remains green

## Stage 3 — Plan and Cleanup

- [ ] Review flow exists
- [ ] Content-free plan exists
- [ ] Every plan item has a stable HMAC path ID
- [ ] Every plan item has an artifact fingerprint
- [ ] Dry-run exists
- [ ] Per-category confirmation exists
- [ ] Final confirmation exists
- [ ] Known disposable artifacts can be deleted
- [ ] Workspace files are never auto-deleted
- [ ] Git data is never auto-modified
- [ ] Secrets produce rotation recommendations
- [ ] Unknown artifacts require manual action
- [ ] Changed artifacts are not deleted
- [ ] Symlink targets are not deleted
- [ ] Deletion result is verified
- [ ] Content-free cleanup evidence is signed
- [ ] Stage 3 tests pass
- [ ] Existing full suite remains green

## Stage 4 — Provider History and Boundary

- [x] Provider exposure inventory exists
- [x] Provider status states exist
- [x] Claude provider action guidance exists
- [x] Codex provider action guidance exists
- [x] Official-source metadata exists
- [x] Provider deletion is never assumed
- [x] User confirmation is recorded content-free
- [x] Protection boundary uses provable timestamps
- [x] Protection boundary is Ed25519-signed
- [x] Boundary includes unresolved local findings
- [x] Boundary includes provider-history status
- [x] Boundary includes active privacy mode
- [x] Boundary includes ZDR certification digest
- [x] Boundary tampering is rejected
- [x] Stage 4 tests pass
- [x] Existing full suite remains green

## Stage 5 — Product Integration

- [ ] `invock privacy onboard` works
- [ ] `invock privacy legacy status` works
- [ ] `invock privacy legacy scan` works
- [ ] `invock privacy legacy review` works
- [ ] `invock privacy legacy plan` works
- [ ] `invock privacy legacy apply` works
- [ ] `invock privacy legacy verify` works
- [ ] `invock privacy legacy provider-actions` works
- [ ] `invock privacy boundary show` works
- [ ] `invock privacy boundary verify` works
- [ ] `invock privacy legacy demo` works
- [ ] `invock init` recommends onboarding
- [ ] First protected session shows legacy status
- [ ] User may skip without false cleanup claim
- [ ] Dashboard shows content-free legacy status
- [ ] API exposes content-free legacy status
- [ ] Stats include content-free remediation counts
- [ ] Stage 5 tests pass
- [ ] Existing full suite remains green

## Stage 6 — Certification and Packaging

- [ ] Runtime-generated canaries exist
- [ ] Scan results contain no canary content
- [ ] Plans contain no canary content
- [ ] Receipts contain no canary content
- [ ] Logs contain no canary content
- [ ] Reports contain no canary content
- [ ] API contains no canary content
- [ ] Dashboard contains no canary content
- [ ] Scanner escape tests pass
- [ ] Cleanup safety tests pass
- [ ] Mutation tests pass
- [ ] Package contains required assets
- [ ] Package contains no runtime data
- [ ] Clean tarball installation passes
- [ ] Commands work outside repository
- [ ] Independent audit passes
- [ ] Final certification passes
- [ ] Existing ZDR certification remains green
- [ ] git diff --check passes
- [ ] Cleanup passes
