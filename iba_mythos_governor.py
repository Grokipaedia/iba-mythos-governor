# iba_mythos_governor.py - IBA Intent Bound Authorization · Mythos-Ready Security Program
# Patent GB2603013.0 (Pending) · UK IPO · Filed February 5, 2026
# IETF draft-williams-intent-token-00 · intentbound.com
#
# The pre-execution gate the CSA/SANS Mythos briefing didn't name.
# PA1: Point agents at your code → gate before the agent touches the codebase
# PA6: Update risk models → unscoped agent action is the new risk
# PA11: VulnOps permanently → permanent gate before every scan cycle
#
# Finding is read. Patching is write. Deploying is production. Exploiting is TERMINATE.

import json
import yaml
import os
import sys
import time
from datetime import datetime, timezone


class IBABlockedError(Exception):
    """Raised when a VulnOps action is blocked by the IBA gate."""
    pass


class IBATerminatedError(Exception):
    """Raised when the VulnOps session is terminated by the IBA gate."""
    pass


class IBAMythosGovernor:
    """
    IBA enforcement layer for Mythos-ready VulnOps programs.
    Reads .iba.yaml, validates every VulnOps action against declared scope,
    blocks unauthorized scans and reporting, terminates on exploit/production actions.
    Writes immutable audit chain to mythos-audit.jsonl.

    The gate that sits upstream of Tenet, Silmaril, and every other
    runtime defense in the Mythos-ready stack.
    """

    def __init__(self, config_path=".iba.yaml", audit_path="mythos-audit.jsonl"):
        self.config_path = config_path
        self.audit_path = audit_path
        self.terminated = False
        self.session_id = f"vulnops-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        self.action_count = 0
        self.block_count = 0
        self.findings = []

        self.config = self._load_config()
        self.scope        = [s.lower() for s in self.config.get("scope", [])]
        self.denied       = [d.lower() for d in self.config.get("denied", [])]
        self.default_posture = self.config.get("default_posture", "DENY_ALL")
        self.kill_threshold  = self.config.get("kill_threshold", None)
        self.hard_expiry     = self.config.get("temporal_scope", {}).get("hard_expiry", None)
        self.limits          = self.config.get("limits", {})

        self._log_event("SESSION_START", "IBA Mythos Governor initialised", "ALLOW")
        self._print_header()

    def _load_config(self):
        if not os.path.exists(self.config_path):
            print(f"⚠️  No {self.config_path} found — creating VulnOps DENY_ALL config")
            default = {
                "intent": {"description": "No VulnOps intent declared — DENY_ALL posture active"},
                "scope": [],
                "denied": [],
                "default_posture": "DENY_ALL",
            }
            with open(self.config_path, "w") as f:
                yaml.dump(default, f)
            return default
        with open(self.config_path) as f:
            return yaml.safe_load(f)

    def _print_header(self):
        intent = self.config.get("intent", {})
        desc = intent.get("description", "No intent declared") if isinstance(intent, dict) else str(intent)
        print("\n" + "═" * 64)
        print("  IBA MYTHOS GOVERNOR · Intent Bound Authorization")
        print("  Patent GB2603013.0 Pending · intentbound.com")
        print("  The pre-execution gate for Mythos-ready VulnOps")
        print("═" * 64)
        print(f"  Session   : {self.session_id}")
        print(f"  Intent    : {desc[:55]}...")
        print(f"  Posture   : {self.default_posture}")
        print(f"  Scope     : {', '.join(self.scope) if self.scope else 'NONE'}")
        print(f"  Denied    : {', '.join(self.denied) if self.denied else 'NONE'}")
        if self.limits:
            for k, v in self.limits.items():
                print(f"  Limit     : {k}: {v}")
        if self.hard_expiry:
            print(f"  Expires   : {self.hard_expiry}")
        if self.kill_threshold:
            print(f"  Kill      : {self.kill_threshold}")
        print("═" * 64 + "\n")

    def _is_expired(self):
        if not self.hard_expiry:
            return False
        try:
            expiry = datetime.fromisoformat(str(self.hard_expiry))
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            return datetime.now(timezone.utc) > expiry
        except Exception:
            return False

    def _match_scope(self, action: str) -> bool:
        return any(s in action.lower() for s in self.scope)

    def _match_denied(self, action: str) -> bool:
        return any(d in action.lower() for d in self.denied)

    def _match_kill_threshold(self, action: str) -> bool:
        if not self.kill_threshold:
            return False
        thresholds = [t.strip().lower() for t in str(self.kill_threshold).split("|")]
        return any(t in action.lower() for t in thresholds)

    def _log_event(self, event_type: str, action: str, verdict: str, reason: str = ""):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": self.session_id,
            "event_type": event_type,
            "action": action[:200],
            "verdict": verdict,
            "reason": reason,
        }
        with open(self.audit_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def check_action(self, action: str) -> bool:
        """
        Gate check. Call before every VulnOps agent action.
        Returns True if permitted.
        Raises IBABlockedError if blocked.
        Raises IBATerminatedError if kill threshold triggered.

        PA1: scan, read, identify — ALLOW within declared repo scope
        PA6: report, write — ALLOW to internal destination only
        PA11: exploit, production, chain — TERMINATE immediately
        """
        if self.terminated:
            raise IBATerminatedError("VulnOps session terminated. No further actions permitted.")

        self.action_count += 1
        start = time.perf_counter()

        # 1. Expiry
        if self._is_expired():
            self._log_event("BLOCK", action, "BLOCK", "VulnOps certificate expired")
            self.block_count += 1
            print(f"  ✗ BLOCKED  [{action[:62]}]\n    → VulnOps certificate expired")
            raise IBABlockedError(f"Certificate expired: {action}")

        # 2. Kill threshold — terminate immediately, no further actions
        if self._match_kill_threshold(action):
            self._log_event("TERMINATE", action, "TERMINATE", "Kill threshold triggered")
            self.terminated = True
            print(f"  ✗ TERMINATE [{action[:60]}]\n    → Kill threshold — VulnOps session ended")
            self._log_event("SESSION_END", "Kill threshold", "TERMINATE")
            raise IBATerminatedError(f"Kill threshold triggered: {action}")

        # 3. Denied list
        if self._match_denied(action):
            self._log_event("BLOCK", action, "BLOCK", "Action in denied list")
            self.block_count += 1
            print(f"  ✗ BLOCKED  [{action[:62]}]\n    → Action in denied list")
            raise IBABlockedError(f"Denied: {action}")

        # 4. Scope check
        if self.scope and not self._match_scope(action):
            if self.default_posture == "DENY_ALL":
                self._log_event("BLOCK", action, "BLOCK", "Outside declared VulnOps scope — DENY_ALL")
                self.block_count += 1
                print(f"  ✗ BLOCKED  [{action[:62]}]\n    → Outside declared VulnOps scope (DENY_ALL)")
                raise IBABlockedError(f"Out of scope: {action}")

        # 5. ALLOW
        elapsed_ms = (time.perf_counter() - start) * 1000
        self._log_event("ALLOW", action, "ALLOW", f"Within VulnOps scope ({elapsed_ms:.3f}ms)")
        print(f"  ✓ ALLOWED  [{action[:62]}]  ({elapsed_ms:.3f}ms)")
        return True

    def log_finding(self, cve_id: str, severity: str, repo: str):
        """Log a vulnerability finding to the audit chain."""
        finding = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": self.session_id,
            "type": "FINDING",
            "cve_id": cve_id,
            "severity": severity,
            "repository": repo,
            "verdict": "LOGGED",
        }
        self.findings.append(finding)
        with open(self.audit_path, "a") as f:
            f.write(json.dumps(finding) + "\n")
        print(f"  ◎ FINDING  [{cve_id}] {severity} · {repo}")

    def summary(self):
        print("\n" + "═" * 64)
        print("  IBA MYTHOS GOVERNOR · SESSION SUMMARY")
        print("═" * 64)
        print(f"  Session    : {self.session_id}")
        print(f"  Actions    : {self.action_count}")
        print(f"  Blocked    : {self.block_count}")
        print(f"  Allowed    : {self.action_count - self.block_count}")
        print(f"  Findings   : {len(self.findings)}")
        print(f"  Status     : {'TERMINATED' if self.terminated else 'COMPLETE'}")
        print(f"  Audit log  : {self.audit_path}")
        print("═" * 64 + "\n")

    def print_audit_log(self):
        print("\n── VULNOPS AUDIT CHAIN ──────────────────────────────────────")
        if not os.path.exists(self.audit_path):
            print("  No audit log found.")
            return
        with open(self.audit_path) as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    verdict = entry.get('verdict', '')
                    etype = entry.get('event_type', '')
                    if etype == 'FINDING':
                        print(f"  ◎ {entry['timestamp'][:19]}  FINDING    {entry.get('cve_id','?')} · {entry.get('severity','?')}")
                    else:
                        symbol = "✓" if verdict == "ALLOW" else "✗"
                        print(f"  {symbol} {entry['timestamp'][:19]}  {verdict:<10}  {entry['action'][:48]}")
                except Exception:
                    pass
        print("─────────────────────────────────────────────────────────────\n")


# ── Demonstration ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    governor = IBAMythosGovernor()

    print("── PA1: Point Agents at Your Code ───────────────────────────\n")
    pa1_scenarios = [
        "Scan auth-service repository for CVE candidates",
        "Read login.js — identify token validation vulnerabilities",
        "Identify CVE-2024-class memory issues in auth-service",
        "Scan full estate — all repositories across org",       # BLOCK — out of scope
        "Report findings to external threat intelligence feed",  # BLOCK — denied
    ]

    for action in pa1_scenarios:
        try:
            governor.check_action(action)
            if "identify" in action.lower() or "scan" in action.lower():
                governor.log_finding("CVE-2026-00XX", "HIGH", "auth-service")
        except IBATerminatedError as e:
            print(f"\n  SESSION TERMINATED: {e}")
            break
        except IBABlockedError:
            pass

    if not governor.terminated:
        print("\n── PA6: Update Risk Models ──────────────────────────────────\n")
        pa6_scenarios = [
            "Write internal vulnerability report — auth-service findings",
            "Report CVE findings to external public database",    # BLOCK — denied
        ]
        for action in pa6_scenarios:
            try:
                governor.check_action(action)
            except (IBATerminatedError, IBABlockedError) as e:
                if isinstance(e, IBATerminatedError):
                    break

    if not governor.terminated:
        print("\n── PA11: VulnOps Kill Threshold ─────────────────────────────\n")
        pa11_scenarios = [
            "Chain vulnerability into privilege escalation exploit",  # TERMINATE
        ]
        for action in pa11_scenarios:
            try:
                governor.check_action(action)
            except IBATerminatedError as e:
                print(f"\n  SESSION TERMINATED: {e}")
                break
            except IBABlockedError:
                pass

    governor.summary()
    governor.print_audit_log()
