# WordPress AI Security Audit Agent
> **Astra Security SDE Take-Home Assignment — AI-Driven WordPress User Enumeration Tool**

An AI-driven WordPress user enumeration and brute-force tool. The LLM (Groq `llama-3.3-70b-versatile`) runs in an agentic loop — it calls HTTP inspection tools, reads the results, and autonomously decides which technique to apply next, rather than following a hardcoded sequence.

---

## Approach & Rationale

### Why an agentic loop instead of a script?

A traditional script always runs the same techniques in the same order regardless of what it finds. The assignment asks for an AI component that *plans and orchestrates*. Here, the LLM:

1. Receives a system prompt describing the available tools and a suggested strategy.
2. Calls tools (HTTP probes, XML-RPC, brute force) and reads their results.
3. Decides what to do next based on findings — skips author redirects if REST API already returned users, passes discovered usernames to the XML-RPC validator, selects the most likely admin for brute force.
4. Writes the final executive summary itself, grounded in the actual tool results.

This is the Vercel AI SDK `generateText` multi-step agentic pattern with `maxSteps: 14`.

### Why Groq (free tier) instead of OpenAI?

The evaluators should be able to run this without needing an OpenAI billing account. Groq provides `llama-3.3-70b-versatile` on a free tier (14,400 req/day). The tool exits with a clear error if the key is missing.

### Enumeration techniques implemented

| Technique | Method | Why |
|-----------|--------|-----|
| REST API `/wp-json/wp/v2/users` | GET + JSON parse | Most reliable; unauthenticated by default |
| Author archive `/?author=N` | GET + 301/302 Location header | Works when REST API is restricted |
| XML-RPC multicall probe | POST + error-code discrimination (403 vs 404) | Detects username validity without authentication |
| Debug log scan `/wp-content/debug.log` | GET + regex extraction | Leaks usernames from PHP error messages |
| Version exposure `/readme.html` | GET | Reveals exact WP version for targeted exploits |
| Brute force `wp-login.php` | POST form + cookie/redirect detection | Validates weak passwords on discovered accounts |

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  CLI Entry Point                 │
│              src/index.ts                        │
│  • Parses --target / -t / TARGET_URL             │
│  • Calls SecurityAuditAgent.runEnumerationLoop() │
│  • Builds final AuditReportSchema                │
│  • Writes console output + JSON report file      │
└────────────────────┬────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────┐
│           SecurityAuditAgent                     │
│              src/agent.ts                        │
│                                                  │
│  generateText(model, system, tools, maxSteps)    │
│       ┌──────────────────────────────────┐       │
│       │  LLM (Groq llama-3.3-70b)        │       │
│       │  ┌──────────┐  ┌─────────────┐   │       │
│       │  │tool call │→ │tool result  │   │       │
│       │  └──────────┘  └──────┬──────┘   │       │
│       │        ↑              │           │       │
│       │        └──────────────┘ (loop)    │       │
│       └──────────────────────────────────┘       │
└────────────────────┬────────────────────────────┘
                     │ tool calls
        ┌────────────┼────────────────┐
        ▼            ▼                ▼
┌──────────────┐ ┌──────────┐ ┌─────────────────┐
│inspectEndpoint│ │probeXmlRpc│ │bruteForceLogin  │
│ src/tools/   │ │ src/tools/│ │ src/tools/      │
│ inspectTool  │ │ inspectTool│ │ inspectTool     │
└──────┬───────┘ └────┬──────┘ └────────┬────────┘
       │              │                  │
       ▼              ▼                  ▼
┌──────────────┐ ┌──────────┐ ┌──────────────────┐
│HTTPInspector │ │HTTPInspect│ │bruteForceWordPress│
│src/inspector │ │src/inspec │ │ src/bruteforce   │
└──────────────┘ └──────────┘ └──────────────────┘
                     │
        ┌────────────▼───────────────┐
        │       AuditReporter        │
        │      src/reporter.ts       │
        │  • Console output          │
        │  • report-<epoch>.json     │
        └────────────────────────────┘
```

**Key design choices:**
- Tools are self-contained: each creates its own `HTTPInspector` instance. No shared state between tool calls.
- The LLM only sees tool descriptions and results — it cannot access raw HTTP internals.
- The agent's final text response IS the executive summary (grounded in actual tool results, not hallucinated).

---

## Setup & Usage

### Prerequisites

- Node.js v18+
- Docker & Docker Compose (for the test WordPress instance)
- A free [Groq API key](https://console.groq.com)

### 1. Start the local WordPress target

```bash
docker-compose up -d
```

Then complete the WordPress setup at `http://localhost:8080`. Create a few users (admin, editor, etc.) to have something to enumerate.

### 2. Install dependencies

```bash
npm install
```

### 3. Configure environment

```bash
cp .env.example .env
# Edit .env and set GROQ_API_KEY=gsk_...
```

### 4. Run the agent

```bash
# Using default target (http://localhost:8080)
npm start

# Using a custom target
npm start -- --target http://localhost:8080
npm start -- -t http://192.168.1.100

# Or via environment variable
TARGET_URL=http://localhost:8080 npm start
```

### 5. Expected output

```
[+] Target: http://localhost:8080
[+] Starting WordPress user enumeration...

[AI Agent] Starting agentic enumeration loop...
[AI Agent] Model: Groq llama-3.3-70b-versatile

[AI Agent] → inspectEndpoint: /wp-json/wp/v2/users
[+] Found users: admin, editor
[AI Agent] → probeXmlRpc (username: admin)
[+] Found users: admin
[AI Agent] → inspectEndpoint: /wp-content/debug.log
[~] HTTP 404 — /wp-content/debug.log
[AI Agent] → bruteForceLogin (user: admin)
[+] Brute force SUCCESS — password: password123

=== AI Executive Summary ===
The agent discovered two WordPress users (admin, editor) via the publicly accessible
REST API endpoint /wp-json/wp/v2/users. The XML-RPC interface confirmed the admin
account's existence through error-code discrimination. Brute force against wp-login.php
succeeded with a weak password, indicating a critical authentication vulnerability.
Immediate remediation is required: restrict the REST API, disable XML-RPC, and enforce
strong password policies with 2FA.

[✔] Enumeration complete.
[✔] Report → report-1784650845510.json
```

---

## Testing

```bash
npm test
```

Tests use Node.js built-in `node:test` — no test framework required. The test suite covers:

- Static config checks (`checks.ts`)
- CLI flag parsing
- `AuditReporter` JSON output formatting and user deduplication
- `HTTPInspector` network resilience (unreachable host → graceful failure)
- Brute force regex patterns (REST API extraction, author redirect, debug log)
- AI integration test (skipped if `GROQ_API_KEY` is not set)

---

## Known Limitations & Trade-offs

| Limitation | Notes |
|------------|-------|
| **LLM non-determinism** | The agent may vary in which tools it calls and in what order across runs. The system prompt enforces a strategy but the LLM may occasionally deviate. |
| **Brute force runtime** | Performs brute forcing against `passwords.txt` with configurable concurrency (`workers: 10`) and delays (`0.05s`). Full 100k password runs will take ~30 mins if not rate-limited. |
| **Groq rate limits** | Free tier: 14,400 req/day, 30 req/min. On a slow network or against a slow target, tool steps may approach limits. |
| **Cookie-based login detection** | The `tryLogin` function uses redirect + cookie header detection. 2FA plugins, CAPTCHA, or custom login flows may cause false negatives. |
| **Author redirect only probes IDs 1–3** | The LLM is instructed to probe up to `/?author=3`. Sites with many users require higher IDs, which the agent will not attempt unless prompted. |
| **XML-RPC validates one username at a time** | The multicall probe is a single-username validator. It's most useful after REST API provides candidate usernames. |
| **No persistent session / cookie jar** | `tryLogin` does not persist cookies between attempts. Some hardened WordPress sites set a required test cookie on first GET that must be echoed back on POST. |

---

## JSON Report Format

```json
{
  "target": "http://localhost:8080",
  "timestamp": "2026-07-21T12:00:00.000Z",
  "techniques_used": [
    "/wp-json/wp/v2/users",
    "XML-RPC Multicall Probe",
    "Brute Force (wp-login.php)"
  ],
  "users": [
    { "username": "admin", "evidence": "/wp-json/wp/v2/users" },
    { "username": "editor", "evidence": "/wp-json/wp/v2/users" }
  ],
  "ai_summary": "[AI Security Agent — Groq llama-3.3-70b]: ...",
  "brute_force": {
    "username": "admin",
    "attempts": 47,
    "successful": true,
    "password": "password123",
    "needs_2fa": false,
    "attempts_per_second": 8.2
  }
}
```
