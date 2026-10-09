"""Adversarial regression checks for CyberGuard's local detection engines."""

from __future__ import annotations

from pathlib import Path
import sys

import pandas as pd

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from digital_impersonation.digital_impersonation_service import analyze_digital_impersonation
from account_takeover.account_takeover_service import analyze_account_takeover


def run_impersonation():
    cases = [
        ("negated credential", "security@acme-corp.com", "Security Team", "We will never ask you to provide your password or OTP. Report suspicious messages.", False),
        ("CEO benign", "ceo@acme-corp.com", "CEO", "The board meeting agenda is attached. No action is required.", False),
        ("obfuscated credential", "ceo@acme-corp-security.top", "CEO", "URGENT. Send your O T P and password immediately. Do not call finance.", True),
        ("BEC", "finance@acme-corp-help.com", "Finance Director", "Transfer the vendor payment to the new beneficiary today. Do not verify this with accounts.", True),
        ("authority threat", "notice@gmail.com", "Income Tax Officer", "Pay the penalty immediately or legal action will follow. Submit your OTP on the verification link.", True),
        ("legitimate awareness", "security@acme-corp.com", "Security Team", "Attackers may ask for OTPs and passwords. CyberGuard will never request them.", False),
    ]
    rows = []
    for i, (name, sender, identity, text, malicious) in enumerate(cases, 1):
        rows.append({
            "message_id": f"adv{i}", "channel": "email", "sender_name": sender,
            "sender_domain": sender.split("@")[-1], "claimed_identity": identity,
            "claimed_role": identity, "claimed_organisation": "Acme Corporation",
            "message_text": text, "context": "adversarial regression"
        })
    result = analyze_digital_impersonation(pd.DataFrame(rows), "Acme Corporation", "acme-corp.com")
    by_id = {str(item["message_id"]): item for item in result["messages"]}
    failures = []
    for i, case in enumerate(cases, 1):
        item = by_id.get(f"adv{i}")
        high = bool(item and str(item.get("risk_level", "")).upper() == "HIGH")
        if case[4] and not high:
            failures.append(f"impersonation malicious case {i} was not HIGH")
        if not case[4] and high:
            failures.append(f"impersonation benign case {i} became HIGH")
    return failures


def run_ato():
    rows = []
    base = pd.Timestamp("2026-10-07 10:00:00")
    # Five accounts attacked from one IP in a short window.
    for i in range(5):
        rows.append({
            "timestamp": base + pd.Timedelta(minutes=i),
            "user_id": f"user{i+1}", "login_status": "failed",
            "ip_address": "203.0.113.200", "location": "Unknown City",
            "device": "Chrome-Windows", "session_action": "login_failed"
        })
    # A concentrated recent burst for one user after a quiet baseline.
    for i in range(6):
        rows.append({
            "timestamp": base + pd.Timedelta(hours=1) + pd.Timedelta(minutes=i),
            "user_id": "burst-user", "login_status": "failed" if i >= 3 else "success",
            "ip_address": "203.0.113.201", "location": "Bengaluru",
            "device": "Unknown-Device", "session_action": "login_failed" if i >= 3 else "login_success"
        })
    events = pd.DataFrame(rows)
    profiles = pd.DataFrame([
        {"user_id": f"user{i+1}", "normal_locations": "Bhubaneswar", "known_devices": "Edge-Windows"} for i in range(5)
    ] + [{"user_id": "burst-user", "normal_locations": "Bhubaneswar", "known_devices": "Edge-Windows"}])
    result = analyze_account_takeover(events, profiles, "Acme Corporation", "acme-corp.com")
    spray_users = {str(item.get("user_id")) for item in result["detections"] if item.get("threat") == "Password Spraying"}
    expected_spray = {f"user{i+1}" for i in range(5)}
    failures = []
    if not expected_spray.issubset(spray_users):
        failures.append("password spraying was not attributed to every targeted user")
    return failures


if __name__ == "__main__":
    failures = run_impersonation() + run_ato()
    if failures:
        print("ADVERSARIAL TESTS FAILED")
        for failure in failures:
            print("-", failure)
        raise SystemExit(1)
    print("ADVERSARIAL TESTS PASSED")
