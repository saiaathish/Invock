# Invock Zero Data Retention

Invock supports exactly two privacy modes: `LOCAL_ZDR` and `END_TO_END_ZDR`.

> Invock processes customer content ephemerally and does not intentionally write it to persistent Invock storage. Immediate physical memory erasure cannot be guaranteed by a managed runtime.

Local ZDR prevents Invock from intentionally persisting customer content within Invock's controlled boundary. End-to-End ZDR additionally requires every declared processor receiving customer content to satisfy the configured ZDR policy. Invock cannot independently prove a third party's internal physical deletion without verifiable provider evidence.

Encrypted persistence remains retention. Encryption does not convert retained customer content into ZDR.

`END_TO_END_ZDR` fails closed for unknown, undeclared, expired, self-attested-only, standard-retention, content-logging, or persistent-content processors. Approval cannot override that failure.

Commands:

```text
invock privacy status
invock privacy mode set local-zdr
invock privacy mode set end-to-end-zdr
invock privacy verify-local
invock privacy verify-end-to-end
invock privacy processors list
invock privacy chain inspect
invock privacy demo
```
