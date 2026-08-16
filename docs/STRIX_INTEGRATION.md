# Strix integration boundary

AgentSec uses Strix as an upstream pentesting and reporting engine. The source is vendored under `vendor/strix/` so the project can pin a reviewed upstream revision and apply local security controls without silently changing Strix behavior.

## Imported components

The vendor snapshot includes the modules needed for the first integration boundary:

- `vendor/strix/strix/agents`: root and child agent construction;
- `vendor/strix/strix/tools`: proxy, reporting, notes, todo, browser/runtime-facing tools and agent graph;
- `vendor/strix/strix/runtime`: Docker sandbox and session lifecycle;
- `vendor/strix/strix/report`: run state, vulnerability artifacts, JSON/CSV/SARIF and Markdown writers;
- `vendor/strix/strix/config`, `core`, `interface`, `llm`, `utils` and `skills`: supporting runtime contracts;
- `vendor/strix/containers`: sandbox image and entrypoint;
- `vendor/strix/scripts`: upstream packaging/runtime helpers.

The snapshot was imported from commit `85513391305171ecc6faffe03da4a8bda5e3febb`. Update it deliberately and record the new commit in `THIRD_PARTY_NOTICES.md`.

## AgentSec boundary

The integration must follow this order:

```text
EngagementConfig
  -> Scope Guard
  -> Egress/target validation
  -> Rate Limiter
  -> Action Approval
  -> Strix runtime
  -> Evidence Store
  -> independent verification
  -> report export
```

Strix must not receive an unbounded target or unrestricted credentials. The adapter must generate a bounded instruction file and pass only the authorized target material. The current AgentSec CLI remains dry-run-only until this adapter exists.

## What we reuse

- Strix's multi-agent lifecycle and tool registration;
- Docker sandbox and runtime/session management;
- Caido/proxy integration and request history;
- skills and vulnerability knowledge packs;
- validated report fields and report artifact writers;
- deduplication, SARIF and usage tracking.

## What we add or replace

- typed engagement scope with default deny;
- program rules as executable policy;
- preflight validation before Strix starts;
- explicit approval for state-changing or destructive actions;
- request budgets and deterministic rate limiting;
- redacted, append-only action receipts;
- evidence hashes and independent reproduction gates;
- Ollama-first local provider defaults;
- final report status that distinguishes candidate, verified and rejected findings.

## Safety rule

Do not expose the vendored Strix CLI as a generic `target` passthrough. A future `agentsec assess` command must accept an engagement configuration, validate every target, and refuse to start when the policy, authorization reference or execution budget is invalid.
