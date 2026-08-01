# Protocol/UI integration notes

The new modules are intentionally adapter-free. Existing MCP transports should call `negotiateProfile` during initialization, pass the selected `profile.version` into their transport/session handling, and translate a rejected result into the transport's protocol error response. They must not infer a downgrade when `AMBIGUOUS_DOWNGRADE` is returned.

The API/dashboard adapter can call `buildReportViewModel` with its activity records before serializing a report. Only the returned view model is displayable; raw records, arguments, payloads, traces, credentials, and authorization material must remain in the adapter's private path.

Protocol diagnostics belong on stderr or the host logger. These helpers do not write to stdout and do not emit secrets.
