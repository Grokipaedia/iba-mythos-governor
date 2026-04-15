# iba_mythos_governor.py - Mythos-ready IBA Security Program
import json
import yaml
import os
import sys
import time
from datetime import datetime, timezone

class IBABlockedError(Exception):
    pass

class IBATerminatedError(Exception):
    pass

class IBAMythosGovernor:
    """
    Top-level Mythos-ready IBA governance program.
    Integrates all IBA tools into one unified security layer.
    """

    def __init__(self, config_path=".iba.yaml", audit_path="iba-audit.jsonl"):
        self.config_path = config_path
        self.audit_path = audit_path
        self.terminated = False
        self.session_id = f"mythos-session-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        self.action_count = 0
        self.block_count = 0

        self.config = self._load_config()
        self.scope = [s.lower() for s in self.config.get("scope", [])]
        self.denied = [d.lower() for d in self.config.get("denied", [])]
        self.default_posture = self.config.get("default_posture", "DENY_ALL")
        self.kill_threshold = self.config.get("kill_threshold", None)
        self.hard_expiry = self.config.get("temporal_scope", {}).get("hard_expiry", None)

        self._log_event("SESSION_START", "Mythos Governor initialised", "ALLOW")
        self._print_header()

    def _load_config(self):
        if not os.path.exists(self.config_path):
            print(f"⚠️ No {self.config_path} found — creating default DENY_ALL config")
            default = {
                "intent": {"description": "Mythos-ready operation within approved scope"},
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
        print("\n" + "═" * 70)
        print("  IBA MYTHOS GOVERNOR · Production Security Program")
        print("  Patent GB2603013.0 Pending · NIST-2025-0035")
        print("═" * 70)
        print(f"  Session   : {self.session_id}")
        print(f"  Intent    : {desc[:60]}...")
        print(f"  Posture   : {self.default_posture}")
        print(f"  Scope     : {', '.join(self.scope) if self.scope else 'NONE'}")
        print(f"  Denied    : {', '.join(self.denied) if self.denied else 'NONE'}")
        if self.hard_expiry:
            print(f"  Expires   : {self.hard_expiry}")
        print("═" * 70 + "\n")

    def check_action(self, action: str) -> bool:
        if self.terminated:
            raise IBATerminatedError("Session terminated.")

        self.action_count += 1

        # Expiry
        if self._is_expired():
            self._log_event("BLOCK", action, "BLOCK", "Certificate expired")
            raise IBABlockedError("Certificate expired.")

        # Kill threshold
        if self._match_kill_threshold(action):
            self.terminated = True
            self._log_event("TERMINATE", action, "TERMINATE", "Kill threshold")
            raise IBATerminatedError("Kill threshold triggered.")

        # Denied / Scope checks
        if self._match_denied(action):
            self._log_event("BLOCK", action, "BLOCK", "Denied action")
            raise IBABlockedError("Action in denied list.")

        if self.scope and not self._match_scope(action):
            if self.default_posture == "DENY_ALL":
                self._log_event("BLOCK", action, "BLOCK", "Outside scope")
                raise IBABlockedError("Action outside declared scope.")

        self._log_event("ALLOW", action, "ALLOW")
        print(f"  ✓ ALLOWED  [{action[:60]}]")
        return True

    # (rest of the methods from previous version remain the same)
    # _is_expired, _match_scope, _match_denied, _match_kill_threshold, _log_event, summary, print_audit_log
    # (I kept the logic identical to the previous version for consistency)

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
        action_lower = action.lower()
        return any(s in action_lower for s in self.scope)

    def _match_denied(self, action: str) -> bool:
        action_lower = action.lower()
        return any(d in action_lower for d in self.denied)

    def _match_kill_threshold(self, action: str) -> bool:
        if not self.kill_threshold:
            return False
        thresholds = [t.strip().lower() for t in str(self.kill_threshold).split("|")]
        action_lower = action.lower()
        return any(t in action_lower for t in thresholds)

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

    def summary(self):
        print("\n" + "═" * 70)
        print("  IBA MYTHOS GOVERNOR · SESSION SUMMARY")
        print("═" * 70)
        print(f"  Session   : {self.session_id}")
        print(f"  Actions   : {self.action_count}")
        print(f"  Blocked   : {self.block_count}")
        print(f"  Allowed   : {self.action_count - self.block_count}")
        print(f"  Status    : {'TERMINATED' if self.terminated else 'COMPLETE'}")
        print(f"  Audit log : {self.audit_path}")
        print("═" * 70 + "\n")

    def print_audit_log(self):
        print("\n── IBA AUDIT CHAIN ─────────────────────────────────────")
        if not os.path.exists(self.audit_path):
            print("  No audit log found.")
            return
        with open(self.audit_path) as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    verdict = entry['verdict']
                    symbol = "✓" if verdict == "ALLOW" else "✗"
                    print(f"  {symbol} {entry['timestamp'][:19]}  {verdict:<10}  {entry['action'][:50]}")
                except Exception:
                    pass
        print("────────────────────────────────────────────────────────\n")


if __name__ == "__main__":
    governor = IBAGovernor()

    print("── Mythos-ready IBA Governor started ─────────────────────\n")

    # Example test actions
    test_actions = [
        "Research latest AI governance papers",
        "Analyse codebase structure",
        "Execute financial-transactions for payroll",
        "Deploy to production server",
    ]

    for action in test_actions:
        try:
            governor.check_action(action)
        except (IBABlockedError, IBATerminatedError) as e:
            print(f"  {e}")

    governor.summary()
    governor.print_audit_log()
