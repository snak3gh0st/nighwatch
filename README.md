# Nighwatch

Linux-first CLI for using AI as a reasoning copilot for authorized bug bounty and security testing.

Nighwatch is not a spray scanner that blindly runs hundreds of templates. It is designed to combine:

1. application observations;
2. local reasoning through Ollama;
3. deterministic security tools;
4. independent verification;
5. reproducible evidence; and
6. a human-reviewable final report.

The central rule is simple: the model may propose the next bounded task, but it never gets direct access to the network, browser, shell, or security tools. Any future execution must pass through the policy and execution controls described below.

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
- a dry-run Tool Gateway.

Real HTTP, browser, shell, scanner, and proxy execution is intentionally disabled in this first slice. The first milestone validates authorization and reasoning contracts before adding components that generate traffic or change state.

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
        |                              (future adapters)
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

The runtime currently uses only the Python standard library. This keeps the control plane easy to audit before adding browser, HTTP, and scanner dependencies.

## Installation

```bash
git clone https://github.com/snak3gh0st/nighwatch.git
cd nighwatch

python3 -m venv .venv
source .venv/bin/activate
python -m pip install '.[dev]'
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

Start with explicit hosts, paths, and `GET` only. Do not use wildcard domains or include subdomains that are not explicitly in scope.

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

The current run command does not send a request. It only shows what the gateway would evaluate:

```bash
nighwatch run \
  --config engagements/example.json \
  --dry-run
```

Without `--dry-run`, execution remains blocked:

```text
execution blocked: the HTTP/browser/shell Tool Gateway is not enabled yet
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

## Recommended implementation order

1. append-only Evidence Store with content hashes and receipts;
2. read-only HTTP adapter with egress pinning and deterministic rate limits;
3. controlled browser adapter for approved workflows;
4. application mapping and authenticated profile comparison;
5. adapters for deterministic reconnaissance and fuzzing tools behind the gateway;
6. independent finding validators and rejection states;
7. report generation in Markdown, JSON, SARIF, and PDF; and
8. explicit approval flows for state-changing tests.

Traditional tools should provide observations, not final authority. Scanner output must never become a finding without verification and reproducible evidence.

## Security rules

Use Nighwatch only against assets for which you have explicit authorization. Read [`SECURITY.md`](SECURITY.md) before adding an execution adapter.

Do not bypass the dry-run block, weaken the scope, expose Ollama remotely, or connect a browser, proxy, scanner, or shell directly to the model. The system needs an egress guard, kill switch, approval flow, complete request logging, and an evidence store before real execution is enabled.

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

Nighwatch is in early development. Review the source, the program rules, and every tool adapter before using it in a real engagement. The current version is a secure planning and dry-run control plane, not an autonomous production pentesting system.
