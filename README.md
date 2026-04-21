# iba-mythos-governor

> **Building a Mythos-ready security program. The pre-execution gate the briefing didn't name.**

---

## The Briefing

Gadi Evron. Rob T. Lee. Jim Reavis. Jen Easterly. Bruce Schneier. Chris Inglis. Phil Venables. Heather Adkins. Rob Joyce. 250 CISOs. 30 pages. April 2026.

**"The AI Vulnerability Storm: Building a Mythos-ready Security Program."**

CSA · SANS · OWASP. The most significant CISO community response to an AI capability announcement ever published.

Three Priority Actions drive the entire program:

- **PA1**: Point agents at your code
- **PA6**: Update risk models and reporting
- **PA11**: Build VulnOps as a permanent organizational function

Every one of them assumes the agent is authorized to act — before it does.

---

## The Missing Layer

**PA1** says point agents at your code.
**PA11** says build VulnOps permanently — agents running continuously across your entire software estate.

What authorized the agent to scan that repo?
To extract those findings?
To report externally?
To patch?
To deploy?

Finding a vulnerability is **read.**
Patching it is **write.**
Deploying the fix is **production access.**
Executing it — even in a sandboxed test — is a **kill threshold.**

Four distinct authorization events. The Mythos-ready security program needs a pre-execution gate before any of them fires.

---

## Why Every Defense PIArena Tested Failed

PIArena tested 153 live platforms. Every prompt injection defense failed.

All of them operated inside the model's reasoning loop. The malicious instruction and the safety instruction are both text. The model interprets both. The injection wins.

IBA operates outside the loop entirely. The `.iba.yaml` certificate is not a prompt. Not a policy. Not a guardrail. It is a cryptographic boundary signed before the agent connects to any codebase, any CI system, any deployment target.

**You cannot inject a cryptographic boundary.**

---

## The Complete Mythos-Ready Stack

```
┌─────────────────────────────────────────────────────────┐
│   Mythos / Glasswing · AI Vulnerability Discovery       │
│   Autonomous zero-day discovery at machine speed        │
└───────────────────────────────┬─────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────┐
│   IBA INTENT BOUND AUTHORIZATION · PRE-EXECUTION GATE   │
│   Signed cert before any VulnOps agent connects         │
│   Declared scope · forbidden actions · kill threshold   │
│   Sub-1ms · Outside the model's reasoning loop          │
│   Cannot be injected · Cannot be reasoned around        │
└───────────────────────────────┬─────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────┐
│   Tenet Security · Runtime Agent Defense                │
│   Agent-Side Simulation · Sub-30ms kill switch          │
│   Sandboxes tool calls · Kills hijacked logic           │
└───────────────────────────────┬─────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────┐
│   Silmaril · Application-Layer Prompt Injection Defense │
│   Self-healing · Multihead classifier · 2x detection   │
└───────────────────────────────┬─────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────┐
│   Authorized · Scoped · Audited Output                  │
│   WitnessBound immutable audit chain                    │
└─────────────────────────────────────────────────────────┘
```

IBA is not competing with Tenet or Silmaril. It is upstream of both.

---

## Quick Start

```bash
git clone https://github.com/Grokipaedia/iba-mythos-governor.git
cd iba-mythos-governor
pip install -r requirements.txt
python iba_mythos_governor.py
```

---

## VulnOps Intent Certificate — .iba.yaml

```yaml
intent:
  description: "Scan auth-service for CVEs and generate internal report. No production. No external reporting. No exploit execution."

scope:
  - repo_read
  - vuln_scan
  - report_write
  - cve_identify

denied:
  - production_deploy
  - secret_access
  - external_report
  - full_estate_scan
  - competitor_scan

default_posture: DENY_ALL

kill_threshold: "exploit_execute | production_deploy | secret_access | chain_vulnerability"

limits:
  repository: "auth-service only"
  report_destination: "internal security team only"

temporal_scope:
  hard_expiry: "2026-12-31"
  session_max_hours: 8

audit:
  chain: witnessbound
  log_every_action: true
```

---

## Gate Logic

```
Certificate valid?                      → PROCEED
Action outside declared scope?          → BLOCK
Forbidden action attempted?             → BLOCK
Kill threshold triggered?               → TERMINATE + LOG
Repo outside declared scope?            → BLOCK
External reporting attempted?           → BLOCK
No certificate present?                 → BLOCK
```

**No cert = No VulnOps agent activation.**

---

## The VulnOps Authorization Events

| Action | Without IBA | With IBA |
|--------|-------------|---------|
| Scan auth-service repo | Implicit — any repo, any depth | Explicit — declared repo only |
| Identify CVE candidates | Implicit — any codebase | Explicit — declared scope only |
| Write internal report | Implicit | Explicit — internal only |
| Report to external feed | No boundary exists | FORBIDDEN — BLOCK |
| Scan full estate | No boundary exists | FORBIDDEN — BLOCK |
| Chain vulnerability | No boundary exists | KILL THRESHOLD — TERMINATE |
| Execute exploit | No boundary exists | KILL THRESHOLD — TERMINATE |
| Deploy patch | No boundary exists | KILL THRESHOLD — TERMINATE |

---

## Specialized Tools — All IBA Governed

| Tool | Purpose |
|------|---------|
| [glasswing-iba-guard](https://github.com/Grokipaedia/glasswing-iba-guard) | Govern the patch. Not just find the bug. |
| [iba-governor](https://github.com/Grokipaedia/iba-governor) | Full production governance · working implementation |
| [iba-code-guard](https://github.com/Grokipaedia/iba-code-guard) | They got the commit. They didn't get the cert. |
| [iba-devstack-governor](https://github.com/Grokipaedia/iba-devstack-governor) | Govern the full dev stack |
| [iba-skill-guard](https://github.com/Grokipaedia/iba-skill-guard) | Govern the skill before it executes |
| [iba-twin-guard](https://github.com/Grokipaedia/iba-twin-guard) | Govern your digital twin |
| [iba-platform-guard](https://github.com/Grokipaedia/iba-platform-guard) | Every managed agent platform |
| [agent-vibe-governor](https://github.com/Grokipaedia/agent-vibe-governor) | Governed vibe coding |

---

## Why IBA. Why Now.

Traditional guardrails — prompts, RLHF, constitutional AI, runtime filters — all operate inside the model's reasoning loop.

IBA moves enforcement from the **model layer** (fragile, injectable) to the **execution layer** (cryptographic, deterministic).

Mythos demonstrated that AI can find and exploit vulnerabilities at a speed and scale that outpaces any defensive deployment process designed for quarterly software releases.

The IBA pre-execution gate is the only control that:

- Exists **before** the agent connects
- Operates **outside** the model's reasoning loop
- Cannot be **injected, overridden, or reasoned around**
- Fires in **sub-1ms**
- Produces an **immutable audit chain**

**Your intent. Your rules. Cryptographically enforced.**

---

## Live Demo

**governinglayer.com/mythos-html/**

VulnOps agent scenario live. Glasswing scan scenario. ALLOW · BLOCK · TERMINATE firing in real time against a realistic VulnOps intent certificate. The complete Mythos-ready stack visualised.

**governinglayer.com/governor-html/**

Interactive gate. Edit the cert. Run any action. Sub-1ms confirmed.

---

## Patent & Standards Record

```
Patent:   GB2603013.0 (Pending) · UK IPO · Filed February 10, 2026
PCT:      150+ countries · Protected until August 2028
IETF:     draft-williams-intent-token-00 · CONFIRMED LIVE
          datatracker.ietf.org/doc/draft-williams-intent-token/
NIST:     13 filings · NIST-2025-0035
NCCoE:    10 filings · AI Agent Identity & Authorization
          Most complete single-framework submission in 319 entries
```

IBA priority date: **February 10, 2026**
Glasswing/Mythos disclosure: **April 2026**
CSA/SANS Mythos briefing: **April 12-13, 2026**
IBA predates all known VulnOps authorization deployments.

---

## Acquisition & Partnership Enquiries

IBA Intent Bound Authorization is available for acquisition, licensing, or strategic partnership.

**Jeffrey Williams**
IBA@intentbound.com
IntentBound.com
Patent GB2603013.0 Pending · IETF draft-williams-intent-token-00
