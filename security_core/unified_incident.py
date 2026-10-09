"""Shared CyberGuard incident and risk conventions.

The three visible detection modules remain independent. This module gives them
one common incident vocabulary for dashboards, history, exports and future
cross-module correlation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional


def _clean(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value).strip()


def normalise_organisation(
    name: Optional[str] = None,
    domain: Optional[str] = None,
) -> Dict[str, str]:
    name = _clean(name, "Organisation") or "Organisation"
    domain = _clean(domain).lower().lstrip("@").rstrip(".")
    return {"name": name, "domain": domain}


def recommendations_for(module: str, attack_type: str, severity: str) -> List[str]:
    module = _clean(module).lower()
    attack_type = _clean(attack_type).lower()
    severity = _clean(severity).upper()

    if module == "account_takeover":
        actions = [
            "Review recent authentication and session activity.",
            "Verify the affected user's identity through a known channel.",
        ]
        if severity == "HIGH":
            actions = [
                "Temporarily lock or step-up authenticate the affected account.",
                "Revoke active sessions and investigate recent authentication events.",
                "Force a credential reset and require MFA before restoring access.",
                *actions,
            ]
        return actions

    if module == "digital_impersonation":
        if "business email compromise" in attack_type:
            return [
                "Do not execute payment, beneficiary or gift-card instructions from the reported message.",
                "Verify the claimed sender through a known, independent contact channel.",
                "Alert Finance/Security and preserve the message and sender infrastructure as evidence.",
                "Block or monitor the reported sender/domain according to organisational policy.",
            ]
        if severity == "HIGH":
            return [
                "Verify the sender through a known independent contact channel.",
                "Do not disclose passwords, OTPs or other secrets.",
                "Report and preserve the message, sender address and suspicious links.",
            ]
        return [
            "Verify the sender before acting.",
            "Avoid sharing credentials or sensitive information until the request is confirmed.",
        ]

    # Phishing and generic communication threats.
    if severity == "HIGH":
        return [
            "Do not click links, scan codes or provide credentials from the reported content.",
            "Quarantine or report the message through the organisation's security process.",
            "Block suspicious sender/domain infrastructure where appropriate.",
        ]
    return [
        "Verify the content through an official channel before acting.",
        "Avoid entering credentials into links supplied by the reported content.",
    ]


def make_incident(
    *,
    module: str,
    severity: str,
    risk_score: int | float,
    confidence: str,
    attack_type: str,
    source: str = "",
    target: str = "",
    evidence: Optional[Iterable[Any]] = None,
    organisation: Optional[str] = None,
    organisation_domain: Optional[str] = None,
    incident_id: Optional[str] = None,
) -> Dict[str, Any]:
    severity = _clean(severity, "UNKNOWN").upper()
    attack_type = _clean(attack_type, "Unclassified Security Event")
    org = normalise_organisation(organisation, organisation_domain)
    evidence_list = [_clean(item) for item in (evidence or []) if _clean(item)]

    if not incident_id:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
        incident_id = f"CG-{stamp[-12:]}"

    return {
        "incident_id": incident_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "module": _clean(module, "unknown"),
        "severity": severity,
        "risk_score": max(0, min(int(round(float(risk_score))), 100)),
        "confidence": _clean(confidence, "LOW").upper(),
        "attack_type": attack_type,
        "source": _clean(source),
        "target": _clean(target),
        "organisation": org,
        "evidence": evidence_list,
        "recommendations": recommendations_for(_clean(module), attack_type, severity),
    }


def build_incident_summary(incidents: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    items = list(incidents or [])
    return {
        "total_incidents": len(items),
        "high": sum(1 for item in items if _clean(item.get("severity")).upper() == "HIGH"),
        "medium": sum(1 for item in items if _clean(item.get("severity")).upper() == "MEDIUM"),
        "low": sum(1 for item in items if _clean(item.get("severity")).upper() == "LOW"),
        "by_module": {
            "phishing": sum(1 for item in items if _clean(item.get("module")).lower() == "phishing"),
            "account_takeover": sum(1 for item in items if _clean(item.get("module")).lower() == "account_takeover"),
            "digital_impersonation": sum(1 for item in items if _clean(item.get("module")).lower() == "digital_impersonation"),
        },
    }
