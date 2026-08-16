# Nighwatch

Linux-first CLI for using AI as a reasoning copilot for authorized bug bounty and security testing.

Nighwatch is not a spray scanner that blindly runs hundreds of templates. It is designed to combine:

1. application observations;
2. local reasoning through Ollama;
3. deterministic security tools;
4. independent verification;
5. reproducible evidence; and
6. a human-reviewable final report.

The central rule is simple: the model may propose the next bounded task, but it never gets direct access to the network, browser, shell, or security tools. Every executable adapter must pass through the policy and execution controls described below. Active methods and payloads remain disabled unless the engagement explicitly enables them.

## Current status

The current slice implements the secure control-plane foundation:

- authorized engagement configuration;
- default-deny scope by scheme, host, port, path, and HTTP method;
- explicit excluded hosts;
- deterministic policy hashing;
- request, concurrency, and cost budgets;
- read-only, state-changing, and destructive action classification;
- redaction of sensitive headers and parameters;
- a local Ollama client with structured JSON output;
- a Planner that proposes one bounded next task; and
- a policy-enforced Tool Gateway;
- a bounded HTTP executor for GET, HEAD, OPTIONS, POST, PUT, PATCH, and DELETE;
- an append-only Evidence Store; and
- a structured Application Map; and
- an independently reproduced authorization validator;
- a controlled, optional Playwright page inspector;
- a fixed-argument traditional-tool registry with a local request-aware proxy adapter; and
- a bounded active probe engine for operator-owned body templates; and
- a bounded multi-step observe-reason-test-verify loop with persisted state.

Arbitrary shell execution, direct scanner execution, arbitrary browser actions,
downloads, form submission through the browser, and HTTPS CONNECT interception
remain disabled. Controlled active HTTP requests require an enabled policy,
an in-scope method, an explicit approval identifier when configured, rate and
concurrency limits, and evidence capture. Tool adapters can run only through
the loopback request-aware proxy and only for HTTP targets until a reviewed
TLS interception adapter is available.

## What Nighwatch is meant to do

The target workflow is:

```text
authorized scope
  -> controlled reconnaissance
  -> application map
  -> authentication analysis
  -> authenticated API and endpoint map
  -> vulnerability hypotheses
  -> bounded tests
  -> observations
  -> adaptive strategy
  -> independent validation
  -> reproducible evidence
  -> impact analysis
  -> final report
```

The model is useful for connecting endpoints, objects, roles, and business flows; comparing authorized user profiles; proposing IDOR/BOLA, broken access control, API authorization, SSRF, XSS, session, and business-logic hypotheses; and identifying which observation is still missing.

The model must never turn a probability estimate into a reportable vulnerability. A finding requires observable evidence, consistent reproduction, and demonstrated impact.

## Safety boundary

The execution boundary is designed as:

```text
Human authorization
        |
        v
EngagementConfig -> Scope Guard -> Rate Limiter -> Action Approval
        |                                      |
        v                                      v
  Ollama Planner                         Tool Gateway
        |                           (HTTP / active / proxy)
        v                                      |
  Task Proposal -------------------------------+
                                               v
                              Request Logger + Evidence Store
```

The policy is an executable restriction, not prompt text. The system must refuse targets outside the declared scheme, host, port, path, method, or engagement window. Model output, discovered links, redirects, DNS results, and scanner output cannot expand scope.

## Requirements

- Python 3.12 or newer;
- Ollama installed locally;
- a local model that supports chat and structured output;
- explicit written authorization for every target; and
- a Linux or macOS terminal for the CLI.

The core runtime uses only the Python standard library. Playwright is an
optional dependency for the controlled browser adapter.

## Installation

```bash
git clone https://github.com/snak3gh0st/nighwatch.git
cd nighwatch

python3 -m venv .venv
source .venv/bin/activate
python -m pip install '.[dev]'
```

Install the optional browser adapter only when browser inspection is needed:

```bash
python -m pip install '.[browser]'
playwright install chromium
```

Validate the installation:

```bash
nighwatch --version
nighwatch --help
pytest
```

The internal Python package remains `agentsec` for compatibility with the first development snapshots. The public command and distribution name are `nighwatch`.

You can also run it directly from the source tree:

```bash
PYTHONPATH=src python -m nighwatch --help
```

Interactive terminals show this startup identity:

```text
NIGHWATCH
scope-enforced AI security lab
by snak3gh0st
AUTHORIZED TARGETS ONLY • EVERY ACTION LOGGED
```

The banner is written to `stderr`, so JSON on `stdout` remains machine-readable. Suppress it in automation with:

```bash
nighwatch --no-banner scope validate --config engagements/example.json
```

`nightwatch` and `agentsec` remain available as command aliases during the migration.

## Configure Ollama

On Apple Silicon, Ollama can use Metal acceleration. On Linux it can use CPU or an available GPU. Keep Ollama on the same host as the CLI and do not expose its API to the network.

Start Ollama if needed:

```bash
ollama serve
```

Download a suitable local model:

```bash
ollama pull qwen2.5-coder:14b
```

Configure Nighwatch:

```bash
export NIGHWATCH_OLLAMA_MODEL=qwen2.5-coder:14b
export NIGHWATCH_OLLAMA_TIMEOUT_SECONDS=180
export NIGHWATCH_OLLAMA_MAX_TOKENS=512
nighwatch llm health
```

The client defaults to `http://127.0.0.1:11434` and rejects remote endpoints. This prevents the local model service from becoming an accidentally exposed network service.

Older `AGENTSEC_OLLAMA_*` variables are still accepted for compatibility. New installations should use `NIGHWATCH_OLLAMA_*`.

## Create an authorized engagement

Create a separate engagement for each program or target:

```bash
mkdir -p engagements
nighwatch init --output engagements/example.json
```

Edit the template only with the rules of a program for which you have explicit authorization. `authorization.artifact_id` should reference the authorization document or ticket; do not put the document, credentials, cookies, or tokens in the configuration.

Example of a deliberately narrow configuration:

```json
{
  "engagement_id": "eng_acme_2026_001",
  "authorization": {
    "artifact_id": "bbp-program-scope-2026-001"
  },
  "allowed_origins": [
    {
      "scheme": "https",
      "host": "authorized.example.com",
      "ports": [443],
      "path_prefixes": ["/api/"],
      "methods": ["GET"]
    }
  ],
  "excluded_hosts": [
    "admin.authorized.example.com"
  ],
  "auth_profiles": [
    "owner_user",
    "non_owner_user"
  ],
  "limits": {
    "requests_per_second": 1.0,
    "max_requests": 100,
    "max_concurrent_requests": 1,
    "max_cost_usd": 1.0
  },
  "actions": {
    "read_only": true,
    "state_mutation": false,
    "destructive": false
  }
}
```

Start with explicit hosts, paths, and `GET` only. Do not use wildcard domains or include subdomains that are not explicitly in scope. Enable active methods only when the program rules explicitly allow the specific operation.

For a controlled active engagement, the origin must list the methods and the
policy must enable active testing. State-changing and destructive actions are
still approval-gated:

```json
{
  "allowed_origins": [
    {
      "scheme": "https",
      "host": "authorized.example.com",
      "ports": [443],
      "path_prefixes": ["/api/test-fixtures/"],
      "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    }
  ],
  "actions": {
    "read_only": true,
    "state_mutation": true,
    "destructive": false,
    "require_state_change_approval": true,
    "require_destructive_approval": true
  },
  "active_testing": {
    "enabled": true,
    "max_payload_bytes": 8192,
    "max_cases": 25,
    "kill_switch_file": ".nighwatch-kill"
  }
}
```

Keep active paths narrower than the read-only application map. Treat the
approval identifier as an operator-controlled local gate in this MVP; it does
not replace the program's written authorization or an external approval
system.

## Validate scope before testing

```bash
nighwatch scope validate --config engagements/example.json
nighwatch policy --config engagements/example.json

nighwatch scope check \
  --config engagements/example.json \
  --method GET \
  --url https://authorized.example.com/api/health
```

The URL check returns exit code `0` when allowed and `2` when rejected. The policy hash identifies the exact effective policy and should accompany future action receipts and evidence.

## Inspect a safe plan

The general orchestration command does not send a request. It only shows what the gateway would evaluate:

```bash
nighwatch run \
  --config engagements/example.json \
  --dry-run
```

Without `--dry-run`, the general orchestration remains blocked:

```text
execution blocked: the general orchestrator is not enabled yet; use an explicit bounded adapter
```

## Run bounded HTTP observations and active requests

Every request passes through the declared scope, action policy, rate limiter,
request budget, concurrency limit, DNS address check, kill switch, receipt
logger, and evidence store. `GET`, `HEAD`, and `OPTIONS` are read-only. `POST`,
`PUT`, and `PATCH` are state-changing. `DELETE` is destructive and should stay
disabled unless the program explicitly authorizes it.

For a profile that needs a bearer token, load the secret into the process environment instead of writing it to the engagement file or shell arguments:

```bash
export NIGHWATCH_AUTH_OWNER_USER_BEARER='token-loaded-outside-the-repository'

nighwatch http request \
  --config engagements/example.json \
  --url https://authorized.example.com/api/orders/123 \
  --method GET \
  --profile owner_user \
  --capture-body
```

For an explicitly authorized state-changing test, keep the body in a file and
pass a local approval identifier. The body is size-limited and is never taken
from an LLM-generated command line:

```bash
printf '%s' '{"name":"nighwatch-canary"}' > /tmp/nighwatch-test-body.json

nighwatch http request \
  --config engagements/authorized-active.json \
  --url https://authorized.example.com/api/test-fixtures/echo \
  --method POST \
  --body-file /tmp/nighwatch-test-body.json \
  --approval-id approval-ticket-123 \
  --capture-body
```

The configured active policy must be enabled, the origin must allow `POST`,
and the approval identifier must be supplied to the gateway process. A
successful response is only an observation; it does not create a finding.

### Run a bounded active probe

`active probe` substitutes one payload at a time into an operator-owned body
template. It enforces `active_testing.max_cases` and
`active_testing.max_payload_bytes`, records an evidence item for each case,
and deliberately returns probe observations rather than vulnerability claims.

```bash
cat > /tmp/nighwatch-body-template.json <<'EOF'
{"name":"{{NIGHWATCH_PAYLOAD}}"}
EOF

printf '%s\n' alpha canary '<marker>' > /tmp/nighwatch-payloads.txt

nighwatch active probe \
  --config engagements/authorized-active.json \
  --url https://authorized.example.com/api/test-fixtures/echo \
  --method POST \
  --body-template-file /tmp/nighwatch-body-template.json \
  --payload-file /tmp/nighwatch-payloads.txt \
  --approval-id approval-ticket-123
```

Cookie-based profiles use `NIGHWATCH_AUTH_OWNER_USER_COOKIE`. The profile name must already exist in `auth_profiles`. Secrets are redacted from receipts and evidence; response bodies are hashed and only a bounded redacted preview is stored when `--capture-body` is selected.

Each execution writes local-only artifacts under `evidence/<engagement_id>/` by default:

```text
receipts.jsonl       authorization and rate decisions
evidence.jsonl       redacted HTTP evidence and body hashes
application_map.json endpoints, paths, parameters, roles, and observations
```

Private or loopback addresses are rejected by default, even when the hostname is in scope. An explicitly authorized local lab may opt in with:

```json
"network": {
  "allow_private_addresses": true
}
```

Do not enable this option for a public bug bounty target unless the program explicitly authorizes the private network path.

## Compare two authorized profiles

For an object-level authorization hypothesis, compare the same endpoint with two declared profiles. The validator performs four read-only requests: owner baseline, subject comparison, and one independent reproduction for each profile.

```bash
export NIGHWATCH_AUTH_OWNER_USER_BEARER='owner-token'
export NIGHWATCH_AUTH_NON_OWNER_USER_BEARER='non-owner-token'

nighwatch authz compare \
  --config engagements/example.json \
  --url https://authorized.example.com/api/orders/123 \
  --owner-profile owner_user \
  --subject-profile non_owner_user \
  --impact-field email
```

The validator requires distinct credential fingerprints, successful responses, a matching object identifier, stable independent reproductions, and an observed impact field before producing a verified report. Results are:

- `verified`: a report is written under `evidence/<engagement_id>/reports/`;
- `candidate`: more human evidence or impact proof is required; or
- `rejected`: the comparison did not satisfy the verification gates.

An HTTP `200` by itself is never enough to create a report.

## Inspect an authorized page with the controlled browser

The optional browser adapter creates a fresh headless Chromium context with no
downloads or granted permissions. Every page request and subresource is sent
through the Scope Guard, approval policy, rate limiter, and receipt logger.
Requests outside scope and state-changing methods are aborted. The adapter
does not click forms, submit data, evaluate model-supplied JavaScript, or
follow a redirect outside the declared scope. It stores page metadata,
sanitized request metadata, cookie metadata without values, and a bounded
redacted text preview.

```bash
nighwatch browser inspect \
  --config engagements/example.json \
  --url https://authorized.example.com/app \
  --profile owner_user \
  --evidence-dir evidence/eng_acme_2026_001
```

The browser dependency is intentionally optional. If a target requires login,
load a declared profile from `NIGHWATCH_AUTH_<PROFILE>_BEARER` or
`NIGHWATCH_AUTH_<PROFILE>_COOKIE`; never place credentials in the configuration
file or command-line arguments.

## Inspect the deterministic tool registry

Traditional tools are represented as fixed adapters, not as an unrestricted
shell. The registry currently describes `httpx`, `katana`, `subfinder`,
`nuclei`, and `ffuf`, including their risk and fixed flags:

```bash
nighwatch tools list
nighwatch tools plan \
  --config engagements/example.json \
  --tool httpx \
  --target https://authorized.example.com/
```

The plan command performs no network activity. A tool can run only through the
loopback request-aware proxy, with fixed arguments and no arbitrary extra
flags. The proxy delegates every HTTP request to the same scope, approval,
rate, kill-switch, DNS, and evidence path used by `nighwatch http request`.
HTTPS `CONNECT` is intentionally rejected because a blind tunnel would hide
the request path and payload from the policy layer.

Start the proxy in a separate terminal. An optional declared profile supplies
credentials from the environment to every proxied request; the credentials do
not appear in the tool command:

```bash
export NIGHWATCH_AUTH_OWNER_USER_BEARER='token-loaded-outside-the-repository'

nighwatch proxy start \
  --config engagements/authorized-active-http.json \
  --auth-profile owner_user \
  --evidence-dir evidence/eng_acme_2026_001
```

Copy the printed loopback URL and execute one of the fixed adapters:

```bash
nighwatch tools run \
  --config engagements/authorized-active-http.json \
  --tool httpx \
  --target http://authorized.example.com/ \
  --proxy-url http://127.0.0.1:PORT
```

Only the registered tool flags are used. `subfinder` remains planning-only
because passive discovery cannot be constrained by the HTTP egress proxy;
`ffuf` is state-change classified and requires active policy plus an explicit
approval. For `ffuf`, provide the same approval identifier when starting the
proxy (so proxied requests inherit it) and when invoking `tools run` (so the
tool action itself is approved). Tool output is an observation and never a
final finding.

## Run a bounded multi-step reasoning loop

`investigate` connects the local planner to the bounded validator. The model
receives only the observation and proposes one task per step. The URL, profile
identities, maximum number of steps, and executable adapters remain outside
the model's authority. Candidate results can produce one short sanitized
observation for the next planner call; repeated proposals stop the loop.

```bash
nighwatch investigate \
  --config engagements/example.json \
  --observation examples/observations/order-api.txt \
  --url https://authorized.example.com/api/orders/123 \
  --owner-profile owner_user \
  --subject-profile non_owner_user \
  --impact-field email \
  --max-steps 3 \
  --model qwen2.5-coder:14b
```

The loop writes `evidence/<engagement_id>/investigation.json`. It stores
observation hashes, sanitized proposals, validation states, and the active
policy hash. It does not persist raw observations, cookies, bearer tokens, or
response bodies in the investigation state file.

The current loop intentionally executes only `compare_authorization` and
`validate_candidate` proposals. Other proposals are returned as `planned`
without network activity. This keeps the first adaptive loop narrow while
preserving the same sequence for future agents:

```text
Observe -> Reason -> Policy check -> Execute -> Evidence -> Verify
```

## Use the Planner with Ollama

An observation is a text file containing facts already collected by an authorized person or tool. It may include endpoints, status codes, non-sensitive headers, response differences, and workflow context. Remove cookies, tokens, credentials, unnecessary personal data, and secrets before saving it.

```bash
nighwatch plan \
  --config engagements/example.json \
  --observation examples/observations/order-api.txt \
  --model qwen2.5-coder:14b
```

The proposal is structured and bounded:

```json
{
  "task_kind": "analyze_authentication",
  "target_ref": "endpoint:ep_orders_get",
  "reason": "determine the authentication requirements",
  "auth_profiles": ["owner_user", "non_owner_user"],
  "expected_evidence": ["authentication mechanism", "access-control behavior"],
  "risk_level": "read_only",
  "confidence": 0.8,
  "approval_required": false
}
```

`target_ref` is an opaque state reference, not an executable URL or filesystem path. A proposal does not authorize network access, confirm a vulnerability, or replace human review.

## Finding verification pipeline

```text
Candidate Finding
  -> Verification
  -> Independent Reproduction
  -> Evidence Collection
  -> Impact Analysis
  -> Final Finding
```

Only the final state is reportable. Evidence should include the relevant request and response, authentication profile, timestamp, policy hash, action receipt, reproduction steps, and a safe impact explanation. State-changing or destructive actions require explicit approval and must remain disabled by default.

## Implemented and next implementation order

Completed in the current MVP:

1. authenticated profile comparison with two or more sessions;
2. bounded reasoning loop with persisted state;
3. independent IDOR/BOLA and API authorization validator;
4. controlled browser observation adapter; and
5. fixed-argument tool registry;
6. policy-gated active HTTP methods and bounded payload probes; and
7. a loopback request-aware proxy for selected HTTP tools.

Next, in order:

1. a reviewed TLS interception adapter for HTTPS tool traffic;
2. authenticated session setup workflows that require explicit human approval;
3. GraphQL and API-specific observation parsers;
4. independent validators for SSRF, XSS, race conditions, and business logic;
5. rejected-finding and reviewer workflows; and
6. report generation in Markdown, JSON, SARIF, and PDF.

Traditional tools should provide observations, not final authority. Scanner output must never become a finding without verification and reproducible evidence.

## Security rules

Use Nighwatch only against assets for which you have explicit authorization. Read [`SECURITY.md`](SECURITY.md) before adding an execution adapter.

Do not weaken the scope, expose Ollama remotely, or connect a browser, proxy,
scanner, or shell directly to the model. Keep the kill switch available:

```bash
export NIGHWATCH_KILL_SWITCH=1
```

or create the configured `.nighwatch-kill` file. Every active adapter checks
the switch before execution and while waiting for a concurrency slot.

## Troubleshooting

### `nighwatch: command not found`

Activate the virtual environment or use the source-tree fallback:

```bash
source .venv/bin/activate
PYTHONPATH=src python -m nighwatch --help
```

### Model not found

```bash
ollama list
ollama pull qwen2.5-coder:14b
nighwatch llm health --model qwen2.5-coder:14b
```

### Ollama is not responding

```bash
ollama serve
nighwatch llm health
```

### Planner is slow

Use a smaller model, keep one execution at a time, and limit output:

```bash
export NIGHWATCH_OLLAMA_MODEL=qwen2.5-coder:14b
export NIGHWATCH_OLLAMA_TIMEOUT_SECONDS=180
export NIGHWATCH_OLLAMA_MAX_TOKENS=512
```

## Project layout

```text
src/agentsec/       compatibility implementation package
src/nighwatch/      public Python module entrypoint
examples/            safe synthetic observations and templates
tests/               unit tests for policy, gateway, planner, and Ollama
docs/                architecture and integration notes
vendor/              reviewed third-party source snapshots
```

## License and project status

Nighwatch is in early development. Review the source, the program rules, and
every adapter before using it in a real engagement. The current version is a
scope-enforced controlled-active testing assistant, not an autonomous
production pentesting system.
