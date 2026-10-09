import re

import pandas as pd


# ============================================================
# DIGITAL IMPERSONATION RISK ENGINE
# ============================================================
# The public six-detector interface is preserved.
# Risk is now based on detector evidence + context correlation.
# The engine additionally returns:
#   - attack_category
#   - confidence
#   - confidence_score
#   - sender_authenticity
#   - dangerous_action
#   - evidence chain
# ============================================================

LOW_THRESHOLD = 30
HIGH_THRESHOLD = 70

DETECTOR_WEIGHTS = {
    "Authority Impersonation": 23,
    "Executive Impersonation": 21,
    "Brand Impersonation": 20,
    "Urgency & Pressure Tactics": 12,
    "Threatening Or Extortion Language": 19,
    "Credential Harvesting Via Impersonation": 28,
}

IDENTITY_THREATS = {
    "Authority Impersonation",
    "Executive Impersonation",
    "Brand Impersonation",
}

PRESSURE_THREATS = {
    "Urgency & Pressure Tactics",
    "Threatening Or Extortion Language",
}


def safe_int(value, default=0):
    try:
        if pd.isna(value):
            return default
        return int(float(value))
    except Exception:
        return default


def safe_float(value, default=0.0):
    try:
        if pd.isna(value):
            return default
        return float(value)
    except Exception:
        return default


def normalise_detection(dataframe, threat_name):
    if dataframe is None or not isinstance(dataframe, pd.DataFrame) or dataframe.empty:
        return pd.DataFrame()
    df = dataframe.copy()
    if "message_id" not in df.columns:
        return pd.DataFrame()
    df["threat"] = threat_name
    return df


def calculate_detector_score(threat, detection):
    base = DETECTOR_WEIGHTS.get(threat, 10)
    bonus = 0

    if threat == "Authority Impersonation":
        signals = safe_int(detection.get("authority_signals"))
        bonus += 12 if signals >= 5 else 8 if signals >= 3 else 4 if signals >= 2 else 0

    elif threat == "Executive Impersonation":
        signals = safe_int(detection.get("executive_signals"))
        bonus += 10 if signals >= 3 else 6 if signals >= 2 else 3 if signals >= 1 else 0

    elif threat == "Brand Impersonation":
        signals = safe_int(detection.get("brand_signals"))
        bonus += 8 if signals >= 4 else 6 if signals >= 3 else 4 if signals >= 2 else 0
        authenticity = safe_float(detection.get("sender_authenticity"), 50)
        if authenticity < 30:
            bonus += 12
        elif authenticity < 45:
            bonus += 7

    elif threat == "Urgency & Pressure Tactics":
        signals = safe_int(detection.get("urgency_signals"))
        blocking = safe_int(detection.get("verification_blocking_signals"))
        bonus += 8 if signals >= 4 else 5 if signals >= 2 else 2 if signals else 0
        if blocking:
            bonus += min(8, blocking * 3)

    elif threat == "Threatening Or Extortion Language":
        signals = safe_int(detection.get("threat_signals"))
        bonus += 12 if signals >= 3 else 7 if signals >= 2 else 3 if signals else 0

    elif threat == "Credential Harvesting Via Impersonation":
        credentials = safe_int(detection.get("credential_signals"))
        redirects = safe_int(detection.get("redirect_signals"))
        blocking = safe_int(detection.get("verification_blocking_signals"))
        bonus += 10 if credentials >= 2 else 6 if credentials else 0
        if redirects:
            bonus += min(10, redirects * 5)
        if blocking:
            bonus += 6

    return base + bonus


def calculate_repetition_bonus(count):
    if count >= 5:
        return 8
    if count >= 3:
        return 5
    if count >= 2:
        return 3
    return 0


def _has_phrase(reasons, phrase):
    return phrase.lower() in str(reasons or "").lower()


def _dangerous_action_from_events(events):
    values = [str(v).upper() for v in events.get("dangerous_action", pd.Series(dtype=str)).dropna().tolist()]
    if "DANGEROUS" in values:
        return "DANGEROUS"
    if "SUSPICIOUS" in values:
        return "SUSPICIOUS"
    return "SAFE"


def _sender_authenticity_from_events(events):
    values = []
    if "sender_authenticity" in events.columns:
        for value in events["sender_authenticity"].dropna().tolist():
            number = safe_float(value, -1)
            if number >= 0:
                values.append(number)
    return min(values) if values else 50


def _attack_category(threats, dangerous_action, sender_authenticity, events):
    threat_set = set(threats)
    text = " ".join(str(v) for v in events.get("reasons", pd.Series(dtype=str)).dropna().tolist()).lower()

    has_exec = "Executive Impersonation" in threat_set
    has_finance = any(term in text for term in [
        "financial", "vendor", "beneficiary", "gift card", "payment", "bank details", "payroll"
    ])
    has_credentials = "Credential Harvesting Via Impersonation" in threat_set
    has_pressure = bool(threat_set & PRESSURE_THREATS)
    has_authority = "Authority Impersonation" in threat_set
    has_brand = "Brand Impersonation" in threat_set

    if has_exec and has_finance and (has_pressure or has_credentials or dangerous_action == "DANGEROUS"):
        return "Business Email Compromise"
    if has_credentials and has_pressure:
        return "Account Verification / Credential Scam"
    if has_authority and (has_pressure or has_credentials):
        return "Authority Impersonation Scam"
    if has_exec and has_credentials:
        return "Executive Impersonation / Credential Theft"
    if has_brand and sender_authenticity < 45:
        return "Brand / Organisation Spoofing"
    if has_credentials:
        return "Credential Harvesting"
    if has_exec:
        return "Executive Impersonation"
    if has_authority:
        return "Authority Impersonation"
    if has_brand:
        return "Brand Impersonation"
    if has_pressure:
        return "Social Engineering / Pressure Tactics"
    return "Suspicious Communication"


def _confidence_score(threats, detector_scores, correlation_bonus, sender_authenticity, dangerous_action, events):
    # Confidence measures agreement/quality of evidence, not severity.
    independent = min(len(set(threats)), 6)
    score = 35 + independent * 8
    if dangerous_action == "DANGEROUS":
        score += 15
    elif dangerous_action == "SUSPICIOUS":
        score += 6
    if correlation_bonus >= 12:
        score += 8
    elif correlation_bonus >= 8:
        score += 5
    if sender_authenticity < 30:
        score += 8
    elif sender_authenticity < 45:
        score += 4

    # Explicit evidence phrases add confidence; vague keyword-only hits do not.
    evidence_count = sum(
        1 for value in events.get("reasons", pd.Series(dtype=str)).dropna().tolist()
        if len(str(value)) > 30
    )
    score += min(10, evidence_count * 2)
    return max(0, min(int(score), 99))


def calculate_correlation_bonus(threats, events=None):
    threat_set = set(threats)
    bonus = 0
    reasons = []

    has_identity = bool(threat_set & IDENTITY_THREATS)
    has_pressure = bool(threat_set & PRESSURE_THREATS)
    has_credentials = "Credential Harvesting Via Impersonation" in threat_set

    if has_identity and has_pressure:
        bonus += 8
        reasons.append("Trusted-identity claim combined with pressure tactics")

    if has_credentials and has_identity:
        bonus += 12
        reasons.append("Credential request delivered through a claimed trusted identity")

    if has_credentials and has_pressure:
        bonus += 8
        reasons.append("Credential request paired with urgency or coercion")

    if events is not None:
        dangerous = _dangerous_action_from_events(events)
        blocking = 0
        if "verification_blocking_signals" in events.columns:
            blocking = sum(safe_int(v) for v in events["verification_blocking_signals"].dropna())

        if dangerous == "DANGEROUS" and has_identity:
            bonus += 8
            reasons.append("Trusted identity is used to request a dangerous action")

        if blocking and (has_identity or has_credentials):
            bonus += 6
            reasons.append("Sender attempts to prevent independent verification")

        if "Brand Impersonation" in threat_set:
            authenticity = _sender_authenticity_from_events(events)
            if authenticity < 35 and (has_pressure or has_credentials):
                bonus += 6
                reasons.append("Low sender authenticity reinforces the impersonation signal")

    # Full social-engineering chain: identity + pressure + credential/dangerous action.
    if has_identity and has_pressure and (has_credentials or (events is not None and _dangerous_action_from_events(events) == "DANGEROUS")):
        bonus += 10
        reasons.append("Full attack chain: identity + pressure + dangerous request")

    return bonus, reasons


def build_risk_report(
    authority_results,
    executive_results,
    brand_results,
    urgency_results,
    threat_results,
    credential_results,
):
    detector_frames = [
        normalise_detection(authority_results, "Authority Impersonation"),
        normalise_detection(executive_results, "Executive Impersonation"),
        normalise_detection(brand_results, "Brand Impersonation"),
        normalise_detection(urgency_results, "Urgency & Pressure Tactics"),
        normalise_detection(threat_results, "Threatening Or Extortion Language"),
        normalise_detection(credential_results, "Credential Harvesting Via Impersonation"),
    ]
    detector_frames = [frame for frame in detector_frames if not frame.empty]

    if not detector_frames:
        return (
            pd.DataFrame(columns=[
                "message_id", "risk_score", "risk_level", "detector_count", "detectors_triggered",
                "attack_category", "confidence", "confidence_score", "sender_authenticity",
                "dangerous_action", "reasons"
            ]),
            pd.DataFrame()
        )

    combined = pd.concat(detector_frames, ignore_index=True, sort=False)
    reports = []
    details = []

    for message_id, message_events in combined.groupby("message_id"):
        unique_detections = message_events.drop_duplicates(subset=["threat"])
        threats = unique_detections["threat"].tolist()
        detector_scores = [
            calculate_detector_score(row["threat"], row)
            for _, row in unique_detections.iterrows()
        ]

        sorted_scores = sorted(detector_scores, reverse=True)
        multipliers = [1.00, 0.85, 0.70, 0.50, 0.35, 0.20]
        weighted_score = sum(score * multipliers[i] for i, score in enumerate(sorted_scores))

        detector_counts = message_events["threat"].value_counts().to_dict()
        repetition_bonus = 0
        evidence_reasons = []

        for threat, count in detector_counts.items():
            bonus = calculate_repetition_bonus(count)
            repetition_bonus += bonus
            if bonus:
                evidence_reasons.append(f"{threat} detected {count} time(s); repeated evidence adds {bonus} risk points")

        correlation_bonus, correlation_reasons = calculate_correlation_bonus(threats, message_events)
        dangerous_action = _dangerous_action_from_events(message_events)
        sender_authenticity = _sender_authenticity_from_events(message_events)
        attack_category = _attack_category(threats, dangerous_action, sender_authenticity, message_events)

        # Action severity is additive, but only when the action is corroborated
        # by an identity/pressure/credential signal.
        action_bonus = 0
        if dangerous_action == "DANGEROUS":
            action_bonus = 8 if (set(threats) & IDENTITY_THREATS or set(threats) & PRESSURE_THREATS) else 3
            evidence_reasons.append("Dangerous requested action materially increases risk")
        elif dangerous_action == "SUSPICIOUS":
            action_bonus = 3

        raw_score = weighted_score + correlation_bonus + repetition_bonus + action_bonus

        if sender_authenticity < 30 and (set(threats) & IDENTITY_THREATS):
            raw_score += 5
            evidence_reasons.append("Very low sender authenticity reinforces the identity mismatch")

        risk_score = min(int(round(raw_score)), 100)

        # Avoid high risk from a single weak identity/urgency keyword.
        if len(threats) == 1 and risk_score >= HIGH_THRESHOLD:
            weak_only = dangerous_action != "DANGEROUS" and sender_authenticity >= 45
            if weak_only:
                risk_score = 69
                evidence_reasons.append("High-risk threshold suppressed because evidence is not independently corroborated")

        if risk_score >= HIGH_THRESHOLD:
            risk_level = "HIGH"
        elif risk_score >= LOW_THRESHOLD:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        confidence_score = _confidence_score(
            threats,
            detector_scores,
            correlation_bonus,
            sender_authenticity,
            dangerous_action,
            message_events,
        )
        confidence = "HIGH" if confidence_score >= 75 else "MEDIUM" if confidence_score >= 55 else "LOW"

        # ====================================================
        # EXPLAINABLE EVIDENCE CHAIN
        # ====================================================
        for _, detection in unique_detections.iterrows():
            threat = detection["threat"]
            reasons = str(detection.get("reasons", "")).strip()
            if reasons:
                evidence_reasons.extend([part.strip() for part in reasons.split("|") if part.strip()])

            if threat == "Brand Impersonation":
                auth = detection.get("sender_authenticity")
                if auth is not None:
                    evidence_reasons.append(f"Sender authenticity score: {safe_float(auth, 50):.0f}/100")

        evidence_reasons = list(dict.fromkeys(evidence_reasons + correlation_reasons))

        reports.append({
            "message_id": str(message_id),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "detector_count": len(threats),
            "detectors_triggered": ", ".join(threats),
            "attack_category": attack_category,
            "confidence": confidence,
            "confidence_score": confidence_score,
            "sender_authenticity": int(round(sender_authenticity)),
            "dangerous_action": dangerous_action,
            "reasons": " | ".join(evidence_reasons),
        })

        for _, detection in message_events.iterrows():
            details.append(detection.to_dict())

    return pd.DataFrame(reports), pd.DataFrame(details)
