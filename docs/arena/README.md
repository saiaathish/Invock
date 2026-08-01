# Invock Arena

`runArena` executes each local scenario in protected and unprotected modes. The
protected invocation is the measured result; the unprotected invocation is a
local comparison baseline. Scenario errors fail closed as blocked and are never
treated as successful execution. Metrics are count-only and selected explicitly
by `options.metrics` or `options.plan.metrics`.
