# Invock ZDR Focus Chain

## Stage 1 — Privacy Foundation

- [x] Exactly two privacy modes exist
- [x] No standard privacy mode exists
- [x] Default mode is LOCAL_ZDR
- [x] Existing config migration works
- [x] Privacy contract schema exists
- [x] Data-class schema exists
- [x] Processor profile schema exists
- [x] Privacy-chain schema exists
- [x] Stable privacy reason codes exist
- [x] Privacy configuration validates
- [ ] Privacy restrictions integrated into persisted receipt path
- [x] Stage 1 tests pass
- [x] Existing full suite remains green

## Stage 2 — Local ZDR

- [ ] Customer-content byte scans across all existing persistence paths pass
- [x] Content-free metadata remains functional
- [x] Pseudonymization uses keyed HMAC
- [x] Pseudonymization key stays outside SQLite
- [ ] Failure, timeout, cancellation, and restart scans complete
- [ ] Stage 2 certification complete

## Stage 3 — End-to-End ZDR

- [x] Processor registry exists
- [x] Profiles are versioned
- [x] Unknown processor blocks
- [x] Standard-retention processor blocks
- [x] Self-attested-only processor blocks
- [x] Expired profile blocks
- [x] Content logging blocks
- [x] Persistent-content processor blocks
- [x] Fully compliant synthetic chain may execute
- [ ] Receipt binding and authorization-engine integration complete
- [x] Stage 3 tests pass

## Stage 4 — Product Integration

- [x] Privacy commands appear in help
- [x] Privacy status/mode/verification/processor/chain/demo commands work
- [x] Claude and Codex wrappers display privacy mode
- [x] Proxy blocks failed End-to-End privacy chain
- [ ] API/dashboard privacy state integration complete

## Stage 5 — Adversarial Certification

- [ ] Full persistence canary scan complete
- [ ] Mutation certification complete
- [ ] Local ZDR certification complete
- [ ] End-to-End ZDR certification complete

## Stage 6 — Packaging and Independent Audit

- [ ] Privacy package audit complete
- [ ] Independent read-only privacy audit complete
- [ ] Final privacy certification complete
