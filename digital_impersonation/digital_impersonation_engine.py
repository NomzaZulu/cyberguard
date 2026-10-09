import re

import pandas as pd


# ============================================================
# CYBERGUARD - DIGITAL IMPERSONATION DETECTION ENGINE
# ============================================================
# Six public detectors are intentionally preserved so the
# existing API/service/frontend contract does not change.
# The detectors now use contextual evidence rather than raw
# keyword presence wherever possible.
#
# Additional evidence produced by this module:
# - sender authenticity
# - dangerous requested action
# - verification manipulation
# - business-email-compromise signals
# - explicit identity-claim signals
# ============================================================


# ============================================================
# INPUT HELPERS
# ============================================================

def _prepare_messages(messages, required_columns=None, optional_columns=None):
    if messages is None or not isinstance(messages, pd.DataFrame):
        return None, list(required_columns or [])

    messages = messages.copy()
    required_columns = list(required_columns or [])
    optional_columns = list(optional_columns or [])

    missing_required = [c for c in required_columns if c not in messages.columns]
    if missing_required:
        return None, missing_required

    for column in optional_columns:
        if column not in messages.columns:
            messages[column] = ""

    return messages, []


def _empty_result(columns):
    return pd.DataFrame(columns=columns)


def ensure_message_id(messages):
    messages = messages.copy()
    if "message_id" in messages.columns and messages["message_id"].notna().any():
        messages["message_id"] = messages["message_id"].fillna("")
        missing = messages["message_id"].astype(str).str.strip() == ""
        if missing.any():
            messages.loc[missing, "message_id"] = [
                f"message_{index}" for index in messages.index[missing]
            ]
        return messages

    messages["message_id"] = [f"message_{index}" for index in range(len(messages))]
    return messages


def _text_of(row, column):
    if column not in row:
        return ""
    value = row[column]
    try:
        if pd.isna(value):
            return ""
    except Exception:
        pass
    return str(value).strip().lower()


def _compile_keywords(keywords):
    alternatives = "|".join(
        re.escape(keyword) for keyword in sorted(keywords, key=len, reverse=True)
    )
    return re.compile(r"(?<!\w)(?:" + alternatives + r")(?!\w)", re.IGNORECASE)


def _count_matches(text, pattern):
    if not text or pattern is None:
        return 0
    return len({m.group(0).lower() for m in pattern.finditer(text)})


def _sentence_prefix(text, start):
    return text[max(
        text.rfind(".", 0, start),
        text.rfind("!", 0, start),
        text.rfind("?", 0, start),
        text.rfind(";", 0, start),
        text.rfind(":", 0, start),
    ) + 1:start]


def _is_negated(text, match_start):
    prefix = _sentence_prefix(text, match_start)
    return bool(re.search(
        r"\b(?:no|never|not|without|do\s+not|don't|will\s+never|"
        r"never\s+request|will\s+not|won't)\b",
        prefix,
        re.IGNORECASE,
    ))


def _count_non_negated_matches(text, pattern):
    if not text or pattern is None:
        return 0
    matched = set()
    for match in pattern.finditer(text):
        if not _is_negated(text, match.start()):
            matched.add(match.group(0).lower())
    return len(matched)


def _matched_phrases(text, pattern, ignore_negation=False):
    if not text or pattern is None:
        return []
    result = []
    seen = set()
    for match in pattern.finditer(text):
        if not ignore_negation and _is_negated(text, match.start()):
            continue
        value = match.group(0).lower()
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _message_body(row):
    return _text_of(row, "message_text")


def _message_context(row):
    fields = [
        "message_text",
        "claimed_identity",
        "claimed_role",
        "claimed_organisation",
    ]
    return " ".join(_text_of(row, field) for field in fields if _text_of(row, field))


def _combined_text(row):
    fields = [
        "message_text",
        "claimed_identity",
        "claimed_role",
        "claimed_organisation",
        "context",
    ]
    return " ".join(_text_of(row, field) for field in fields if _text_of(row, field))


# ============================================================
# VOCABULARIES
# ============================================================

AUTHORITY_KEYWORDS = {
    "police", "cbi", "ed", "income tax", "it department", "government",
    "govt", "government of india", "court", "judge", "summon", "traffic",
    "cyber cell", "supreme court", "high court", "district court", "aadhaar",
    "pan card", "election commission", "tax department", "customs",
    "fraud department", "bank official", "officer", "inspector", "commissioner",
    "magistrate", "ombudsman", "superintendent", "sheriff", "collector",
    "tehsildar", "warden", "prosecutor", "regulator", "regulatory authority",
}

FINANCIAL_KEYWORDS = {
    "bank", "sbi", "hdfc", "icici", "axis bank", "kotak", "punjab national",
    "bank of baroda", "canara bank", "upi", "net banking", "netbanking", "atm",
    "debit card", "credit card", "kyc", "account closure", "account freeze",
    "payment gateway", "merchant", "transaction", "beneficiary", "vendor payment",
    "invoice", "reimbursement", "payroll", "salary", "gift card",
}

EXECUTIVE_KEYWORDS = {
    "ceo", "cfo", "cto", "coo", "md", "managing director", "director",
    "chairman", "chairperson", "founder", "owner", "hr", "human resources",
    "finance department", "accounts department", "payroll", "admin", "administrator",
    "ceo office", "board", "vice president", "vp", "head of department", "hod",
    "principal", "dean", "registrar", "vice chancellor", "trustee", "security team",
    "it security", "helpdesk", "support team",
}

EXECUTIVE_IDENTITY_KEYWORDS = {
    "ceo", "cfo", "cto", "coo", "md", "managing director", "director", "chairman",
    "chairperson", "founder", "owner", "ceo office", "vice president", "vp",
    "head of department", "hod", "principal", "dean", "registrar", "vice chancellor",
    "trustee", "security officer", "security team", "hr manager", "finance officer",
    "accounts manager", "it administrator", "it security team",
}

URGENCY_KEYWORDS = {
    "urgent", "immediately", "right now", "within 24 hours", "within 2 hours", "asap",
    "final warning", "last warning", "expire", "expiring", "suspended", "suspension",
    "pending", "legal action", "arrest", "penalty", "fine", "blocked", "deactivate",
    "deactivation", "failure to comply", "act now", "before midnight", "today itself",
    "no time", "hurry", "deadline", "before 5 pm", "within 30 minutes",
}

THREAT_KEYWORDS = {
    "arrest", "warrant", "prosecut", "court notice", "legal action", "jail", "police station",
    "crime branch", "fraud case", "money laundering", "case registered", "complaint filed",
    "notice under", "section 138", "penalty proceedings", "attachment", "property attached",
    "freeze order", "account will be frozen", "disciplinary action", "account suspension",
    "salary processing will be delayed", "access will be blocked",
}

CREDENTIAL_KEYWORDS = {
    "otp", "one time password", "verification code", "pin", "cvv", "atm pin", "password",
    "passcode", "login credentials", "share your password", "card number", "account number",
    "confirm your otp", "send the code", "verify your identity with otp", "bank credentials",
    "net banking password", "seed phrase", "private key", "security code", "employee id",
    "pan number", "aadhaar number",
}

REDIRECT_KEYWORDS = {
    "click here", "click the link", "link below", "http", "https", "www.", "scan the qr",
    "scan this qr", "open the link", "download the app", "install the app", "update your browser",
    "verify now", "click the blue link", "bit.ly", "tinyurl", "fill the form", "submit details",
    "verification portal", "secure form",
}

VERIFICATION_BLOCKING_KEYWORDS = {
    "do not tell", "don't tell", "do not inform", "don't inform", "do not call", "don't call",
    "do not discuss", "don't discuss", "do not verify", "don't verify", "keep this secret",
    "keep it confidential", "confidential", "secretly", "do not contact", "do not involve",
    "do not contact finance", "do not contact the helpdesk", "do not contact the department",
}

INTERNAL_CODENAME_KEYWORDS = {
    "payroll update", "vendor change", "invoice", "purchase order", "tender", "rfq", "quotation",
    "advance payment", "salary revision", "transfer the amount", "bank details change",
    "account change", "new account number", "ifs code change", "beneficiary change",
    "confidential project", "acquisition", "merger", "funding round", "due diligence",
    "gift cards", "gift card codes", "supplier payment",
}

ACTION_KEYWORDS = {
    "send", "share", "provide", "submit", "confirm", "verify", "update", "change", "transfer",
    "pay", "purchase", "download", "install", "click", "open", "scan", "reply", "respond",
    "activate", "unlock", "login", "log in", "sign in", "reset", "authorize", "authorise",
    "approve", "forward", "upload", "enter", "complete",
}

SENSITIVE_ACTION_KEYWORDS = {
    "otp", "password", "pin", "cvv", "verification code", "bank account", "account number",
    "card number", "bank details", "beneficiary", "credential", "passcode", "security code",
    "private key", "seed phrase", "employee id", "pan number", "aadhaar number",
}

PAYMENT_ACTION_KEYWORDS = {
    "transfer", "payment", "pay", "purchase", "gift card", "gift cards", "beneficiary",
    "bank details", "vendor payment", "invoice", "advance payment", "supplier payment",
    "change the vendor bank", "new bank details",
}

IDENTITY_CLAIM_PATTERNS = [
    re.compile(r"\b(?:i am|i'm|this is|speaking as|writing as)\s+(?:the\s+)?(?:ceo|cfo|cto|coo|director|founder|hr|finance|security|registrar|officer)\b", re.I),
    re.compile(r"\b(?:message|notice|request)\s+(?:is|comes)\s+from\s+(?:the\s+)?(?:ceo|hr|finance|security|police|income tax|registrar)\b", re.I),
]

NEGATED_CREDENTIAL_PHRASES = {
    "no password", "no otp", "no pin", "no cvv", "never share your password",
    "never share your otp", "never request your password", "never request your otp",
    "will never request your password", "will never request your otp",
    "do not send your password", "do not send your otp", "do not share your password",
    "do not share your otp", "we will never ask for your password", "we will never ask for your otp",
}

FREE_EMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com",
    "proton.me", "protonmail.com", "icloud.com", "mail.com",
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "shop", "online", "site", "info", "biz", "live", "vip",
    "icu", "work", "support", "club", "rest", "cyou",
}

URL_PATTERN = re.compile(
    r"(https?://|www\.)\S+|\b\S+\.(com|net|org|in|co\.in|edu|gov|gov\.in|ac\.in|edu\.in|biz|xyz|top|info|ru|uk)\b",
    re.I,
)

AUTHORITY_PATTERN = _compile_keywords(AUTHORITY_KEYWORDS)
FINANCIAL_PATTERN = _compile_keywords(FINANCIAL_KEYWORDS)
EXECUTIVE_PATTERN = _compile_keywords(EXECUTIVE_KEYWORDS)
EXECUTIVE_IDENTITY_PATTERN = _compile_keywords(EXECUTIVE_IDENTITY_KEYWORDS)
URGENCY_PATTERN = _compile_keywords(URGENCY_KEYWORDS)
THREAT_PATTERN = _compile_keywords(THREAT_KEYWORDS)
CREDENTIAL_PATTERN = _compile_keywords(CREDENTIAL_KEYWORDS)
REDIRECT_PATTERN = _compile_keywords(REDIRECT_KEYWORDS)
VERIFICATION_BLOCKING_PATTERN = _compile_keywords(VERIFICATION_BLOCKING_KEYWORDS)
INTERNAL_CODENAME_PATTERN = _compile_keywords(INTERNAL_CODENAME_KEYWORDS)
ACTION_PATTERN = _compile_keywords(ACTION_KEYWORDS)
SENSITIVE_ACTION_PATTERN = _compile_keywords(SENSITIVE_ACTION_KEYWORDS)
PAYMENT_ACTION_PATTERN = _compile_keywords(PAYMENT_ACTION_KEYWORDS)


def _has_action_signal(text):
    return _count_matches(text, ACTION_PATTERN) > 0


def _has_sensitive_action(text):
    return _count_non_negated_matches(text, SENSITIVE_ACTION_PATTERN) > 0


def _identity_claim_count(text):
    count = sum(bool(pattern.search(text)) for pattern in IDENTITY_CLAIM_PATTERNS)
    return min(count, 2)


def _verification_blocking_count(text):
    return _count_non_negated_matches(text, VERIFICATION_BLOCKING_PATTERN)


def _domain_tld(domain):
    domain = str(domain or "").strip().lower().rstrip(".")
    if not domain or "." not in domain:
        return ""
    return domain.rsplit(".", 1)[-1]


def _organisation_tokens(organisation):
    return {
        token for token in re.findall(r"[a-z0-9]+", str(organisation or "").lower())
        if len(token) > 2 and token not in {"corporation", "company", "limited", "ltd", "private"}
    }


def _domain_tokens(domain):
    return set(re.findall(r"[a-z0-9]+", str(domain or "").lower()))


def _looks_like_free_email(domain):
    return str(domain or "").strip().lower() in FREE_EMAIL_DOMAINS


def _sender_authenticity(row):
    """Return 0-100 authenticity score and evidence. Higher = more trustworthy."""
    domain = _text_of(row, "sender_domain")
    organisation = _text_of(row, "claimed_organisation") or _text_of(row, "organisation_context")
    organisation_domain = _text_of(row, "organisation_domain")
    if not domain or "." not in domain:
        return 35, ["Sender has no conventional organisation domain"]

    if "@" in domain:
        domain = domain.split("@", 1)[-1]

    org_tokens = _organisation_tokens(organisation)
    reference_domain = organisation_domain
    reference_tokens = _domain_tokens(reference_domain) if reference_domain else set()
    dom_tokens = _domain_tokens(domain)
    shared = org_tokens & dom_tokens

    score = 55
    evidence = []

    if reference_tokens and reference_tokens <= dom_tokens:
        score += 20
        evidence.append("sender domain matches the configured organisation domain")
    elif reference_tokens and not (reference_tokens & dom_tokens):
        score -= 20
        evidence.append("sender domain does not match the configured organisation domain")

    if _looks_like_free_email(domain):
        score -= 25
        evidence.append(f"free-mail domain: {domain}")

    tld = _domain_tld(domain)
    if tld in SUSPICIOUS_TLDS:
        score -= 20
        evidence.append(f"commonly abused TLD: .{tld}")

    if org_tokens and shared:
        score += 30
        evidence.append("sender domain contains organisation identifier")

        # Exact organisation token coverage is stronger than one shared token.
        if len(shared) >= min(2, len(org_tokens)):
            score += 10
            evidence.append("multiple organisation tokens match the sender domain")
    elif org_tokens:
        score -= 30
        evidence.append("sender domain does not contain the claimed organisation identifier")

    # Common lookalike separators / suffixes.
    if org_tokens and any(
        token in dom_tokens for token in {"secure", "support", "login", "verify", "alert", "update", "portal", "notice"}
    ):
        score -= 10
        evidence.append("domain adds a security/support/login-style impersonation suffix")

    return max(0, min(score, 100)), evidence


def _dangerous_action(text):
    """Classify the requested action: SAFE, SUSPICIOUS, or DANGEROUS."""
    credential = _count_non_negated_matches(text, SENSITIVE_ACTION_PATTERN)
    payment = _count_non_negated_matches(text, PAYMENT_ACTION_PATTERN)
    redirect = _count_matches(text, REDIRECT_PATTERN)

    # Explicit secret requests are dangerous even without a URL.
    if credential >= 1 and re.search(
        r"\b(?:send|share|provide|enter|submit|confirm|give|reply with)\b.{0,80}\b(?:otp|password|pin|cvv|verification code|security code|credentials)\b",
        text,
        re.I,
    ):
        return "DANGEROUS", "Requests a password, OTP, PIN, CVV or verification secret"

    if payment >= 1 and re.search(
        r"\b(?:send|transfer|pay|purchase|change|update|use|approve|process)\b",
        text,
        re.I,
    ):
        return "DANGEROUS", "Requests a financial, beneficiary, vendor or gift-card action"

    if redirect and (credential or payment):
        return "DANGEROUS", "Combines a redirect with sensitive information or financial action"

    if redirect or credential or payment:
        return "SUSPICIOUS", "Requests a potentially sensitive action"

    return "SAFE", "No materially dangerous action detected"


def _is_explicit_credential_request(text):
    if not text:
        return False
    if _count_non_negated_matches(text, CREDENTIAL_PATTERN) == 0:
        return False
    return bool(re.search(
        r"\b(?:send|share|provide|submit|confirm|enter|give|reply with|tell us|tell me|upload)\b.{0,100}\b(?:otp|password|pin|cvv|verification code|security code|credentials|card number|account number)\b",
        text,
        re.I,
    ))


def _sender_domain_for_row(row):
    domain = _text_of(row, "sender_domain")
    if "@" in domain:
        return domain.split("@", 1)[-1]
    return domain


# ============================================================
# DETECTOR 1 - AUTHORITY IMPERSONATION
# ============================================================

def detect_authority_impersonation(messages):
    messages, _ = _prepare_messages(messages, optional_columns=[
        "message_id", "message_text", "claimed_identity", "claimed_role",
        "claimed_organisation", "sender_domain", "sender_name", "channel", "timestamp"
    ])
    if messages is None:
        return _empty_result(["message_id", "authority_signals", "claimed_identity", "channel", "timestamp", "reasons", "risk"])
    messages = ensure_message_id(messages)
    records = []

    for _, row in messages.iterrows():
        text = _message_context(row)
        body = _message_body(row)
        body_hits = _count_matches(body, AUTHORITY_PATTERN)
        metadata_hits = _count_matches(
            " ".join([
                _text_of(row, "claimed_identity"),
                _text_of(row, "claimed_role"),
                _text_of(row, "claimed_organisation"),
            ]),
            AUTHORITY_PATTERN,
        )
        hits = max(body_hits, metadata_hits)
        urgency = _count_non_negated_matches(text, URGENCY_PATTERN)
        threat = _count_non_negated_matches(text, THREAT_PATTERN)
        credential = _count_non_negated_matches(text, CREDENTIAL_PATTERN)
        identity_claim = bool(_text_of(row, "claimed_identity") or _text_of(row, "claimed_role"))
        explicit_claim = _identity_claim_count(body)
        action = _has_action_signal(body)

        if hits < 1:
            continue

        # A role such as "Registrar" or "Officer" in a trusted
        # metadata field is not itself an impersonation event. The
        # message must actually invoke the authority in its body, make
        # an explicit identity claim, or use that identity to pressure
        # the recipient into an action. This is a major false-positive
        # control for legitimate institutional notices.
        if not (
            body_hits
            or explicit_claim
            or (identity_claim and (action or urgency or threat or credential))
        ):
            continue

        reasons = [f"Authority identity detected ({hits} indicator(s))"]
        if explicit_claim:
            reasons.append("Message explicitly presents the sender as an authority")
        if threat:
            reasons.append("Authority claim is paired with coercive language")
        if credential:
            reasons.append("Authority claim is paired with a sensitive-information request")

        records.append({
            "message_id": row.get("message_id"),
            "authority_signals": hits,
            "claimed_identity": row.get("claimed_identity", ""),
            "channel": row.get("channel", ""),
            "timestamp": row.get("timestamp", ""),
            "sender_domain": row.get("sender_domain", ""),
            "sender_name": row.get("sender_name", ""),
            "reasons": " | ".join(reasons),
            "risk": "HIGH" if credential or threat >= 2 else "MEDIUM",
        })

    return pd.DataFrame(records) if records else _empty_result([
        "message_id", "authority_signals", "claimed_identity", "channel", "timestamp",
        "sender_domain", "sender_name", "reasons", "risk"
    ])


# ============================================================
# DETECTOR 2 - EXECUTIVE / SENIOR AUTHORITY
# ============================================================

def detect_executive_impersonation(messages):
    messages, _ = _prepare_messages(messages, optional_columns=[
        "message_id", "message_text", "claimed_identity", "claimed_role",
        "claimed_organisation", "sender_domain", "sender_name", "channel", "timestamp"
    ])
    if messages is None:
        return _empty_result(["message_id", "executive_signals", "claimed_role", "channel", "timestamp", "reasons", "risk"])
    messages = ensure_message_id(messages)
    records = []

    for _, row in messages.iterrows():
        body = _message_body(row)
        text = _message_context(row)
        hits = _count_matches(text, EXECUTIVE_PATTERN)
        body_identity_hits = _count_matches(body, EXECUTIVE_IDENTITY_PATTERN)
        explicit_claim = _identity_claim_count(body)
        codename = _count_matches(body, INTERNAL_CODENAME_PATTERN)
        urgency = _count_non_negated_matches(text, URGENCY_PATTERN)
        threat = _count_non_negated_matches(text, THREAT_PATTERN)
        credential = _count_non_negated_matches(text, CREDENTIAL_PATTERN)
        payment = _count_non_negated_matches(text, PAYMENT_ACTION_PATTERN)

        if hits < 1:
            continue
        if not (body_identity_hits or explicit_claim or codename or urgency or threat or credential or payment):
            continue

        reasons = [f"Senior/internal authority role detected ({hits} indicator(s))"]
        if explicit_claim:
            reasons.append("Message contains an explicit identity claim")
        if payment:
            reasons.append("Executive identity is paired with a financial or vendor action")
        if codename:
            reasons.append("Request references a sensitive internal business process")
        if credential:
            reasons.append("Executive identity is paired with a sensitive-information request")

        records.append({
            "message_id": row.get("message_id"),
            "executive_signals": hits,
            "claimed_role": row.get("claimed_role", ""),
            "channel": row.get("channel", ""),
            "timestamp": row.get("timestamp", ""),
            "sender_domain": row.get("sender_domain", ""),
            "sender_name": row.get("sender_name", ""),
            "reasons": " | ".join(reasons),
            "risk": "HIGH" if (credential or payment or codename) else "MEDIUM",
        })

    return pd.DataFrame(records) if records else _empty_result([
        "message_id", "executive_signals", "claimed_role", "channel", "timestamp",
        "sender_domain", "sender_name", "reasons", "risk"
    ])


# ============================================================
# DETECTOR 3 - BRAND / ORGANISATION IMPERSONATION
# ============================================================

def detect_brand_impersonation(messages):
    messages, _ = _prepare_messages(messages, optional_columns=[
        "message_id", "message_text", "claimed_identity", "claimed_organisation",
        "sender_name", "sender_domain", "claimed_role", "channel", "timestamp",
        "organisation_domain", "organisation_context"
    ])
    if messages is None:
        return _empty_result(["message_id", "brand_signals", "claimed_organisation", "sender_domain", "channel", "timestamp", "reasons", "risk"])
    messages = ensure_message_id(messages)
    records = []

    for _, row in messages.iterrows():
        text = _message_context(row)
        org = _text_of(row, "claimed_organisation")
        domain = _sender_domain_for_row(row)
        financial = _count_matches(text, FINANCIAL_PATTERN)
        credential = _count_non_negated_matches(text, CREDENTIAL_PATTERN)
        redirect = _count_matches(text, REDIRECT_PATTERN)
        urgency = _count_non_negated_matches(text, URGENCY_PATTERN)
        payment = _count_non_negated_matches(text, PAYMENT_ACTION_PATTERN)

        authenticity, auth_evidence = _sender_authenticity(row)
        lookalike = bool(org and domain and "." in domain and authenticity <= 45 and not _looks_like_free_email(domain))
        free_mail = _looks_like_free_email(domain)
        suspicious_tld = _domain_tld(domain) in SUSPICIOUS_TLDS
        org_tokens = _organisation_tokens(org)
        domain_tokens = _domain_tokens(domain)
        shared = org_tokens & domain_tokens

        infrastructure_signal = lookalike or free_mail or suspicious_tld
        content_signal = financial >= 2 and (payment or urgency or credential or redirect)

        if not (infrastructure_signal or content_signal):
            continue

        reasons = []
        if infrastructure_signal:
            reasons.extend(auth_evidence)
        if content_signal:
            reasons.append(f"Message contains organisation/financial context ({financial} indicator(s))")
        if not shared and org_tokens and domain:
            reasons.append("Sender domain does not contain the claimed organisation identifier")
        if credential:
            reasons.append("Organisation claim is paired with a sensitive-information request")
        if payment:
            reasons.append("Organisation claim is paired with a financial action")

        signal_count = max(1, financial) + int(infrastructure_signal) + int(credential > 0) + int(payment > 0)
        risk = "HIGH" if (lookalike and (credential or payment or urgency or redirect)) or (free_mail and credential) else "MEDIUM"

        records.append({
            "message_id": row.get("message_id"),
            "brand_signals": signal_count,
            "claimed_organisation": row.get("claimed_organisation", ""),
            "sender_domain": row.get("sender_domain", ""),
            "sender_name": row.get("sender_name", ""),
            "sender_authenticity": authenticity,
            "channel": row.get("channel", ""),
            "timestamp": row.get("timestamp", ""),
            "reasons": " | ".join(dict.fromkeys(reasons)),
            "risk": risk,
        })

    return pd.DataFrame(records) if records else _empty_result([
        "message_id", "brand_signals", "claimed_organisation", "sender_domain", "sender_name",
        "sender_authenticity", "channel", "timestamp", "reasons", "risk"
    ])


# ============================================================
# DETECTOR 4 - URGENCY / PRESSURE / VERIFICATION MANIPULATION
# ============================================================

def detect_urgency_manipulation(messages):
    messages, _ = _prepare_messages(messages, optional_columns=[
        "message_id", "message_text", "claimed_identity", "claimed_role",
        "claimed_organisation", "sender_domain", "sender_name", "channel", "timestamp"
    ])
    if messages is None:
        return _empty_result(["message_id", "urgency_signals", "channel", "timestamp", "reasons", "risk"])
    messages = ensure_message_id(messages)
    records = []

    for _, row in messages.iterrows():
        text = _message_context(row)
        body = _message_body(row)
        urgency = _count_non_negated_matches(text, URGENCY_PATTERN)
        blocking = _verification_blocking_count(body)
        action = _has_action_signal(text)
        dangerous_level, dangerous_reason = _dangerous_action(text)
        identity = bool(_text_of(row, "claimed_identity") or _text_of(row, "claimed_role"))

        # Ordinary deadlines are not enough. Require a concrete action,
        # identity context, or verification manipulation.
        if urgency < 1 and blocking < 1:
            continue
        if not (action or identity or blocking):
            continue

        reasons = []
        if urgency:
            reasons.append(f"Pressure language detected ({urgency} indicator(s))")
        if blocking:
            reasons.append(f"Verification manipulation detected ({blocking} indicator(s))")
        if dangerous_level != "SAFE":
            reasons.append(dangerous_reason)

        records.append({
            "message_id": row.get("message_id"),
            "urgency_signals": urgency,
            "verification_blocking_signals": blocking,
            "dangerous_action": dangerous_level,
            "channel": row.get("channel", ""),
            "timestamp": row.get("timestamp", ""),
            "sender_domain": row.get("sender_domain", ""),
            "sender_name": row.get("sender_name", ""),
            "reasons": " | ".join(dict.fromkeys(reasons)),
            "risk": "HIGH" if blocking and dangerous_level == "DANGEROUS" else "MEDIUM",
        })

    return pd.DataFrame(records) if records else _empty_result([
        "message_id", "urgency_signals", "verification_blocking_signals", "dangerous_action",
        "channel", "timestamp", "sender_domain", "sender_name", "reasons", "risk"
    ])


# ============================================================
# DETECTOR 5 - THREAT / EXTORTION
# ============================================================

def detect_threat_language(messages):
    messages, _ = _prepare_messages(messages, optional_columns=[
        "message_id", "message_text", "claimed_identity", "claimed_role",
        "claimed_organisation", "sender_domain", "sender_name", "channel", "timestamp"
    ])
    if messages is None:
        return _empty_result(["message_id", "threat_signals", "channel", "timestamp", "reasons", "risk"])
    messages = ensure_message_id(messages)
    records = []

    for _, row in messages.iterrows():
        text = _message_context(row)
        threat = _count_non_negated_matches(text, THREAT_PATTERN)
        urgency = _count_non_negated_matches(text, URGENCY_PATTERN)
        credential = _count_non_negated_matches(text, CREDENTIAL_PATTERN)
        action = _has_action_signal(text)
        if threat < 1:
            continue
        if not (action or urgency or credential):
            continue

        reasons = [f"Coercive/threatening language detected ({threat} indicator(s))"]
        if urgency:
            reasons.append("Threat is paired with a time-pressure signal")
        if credential:
            reasons.append("Threat is paired with a sensitive-information request")

        records.append({
            "message_id": row.get("message_id"),
            "threat_signals": threat,
            "channel": row.get("channel", ""),
            "timestamp": row.get("timestamp", ""),
            "sender_domain": row.get("sender_domain", ""),
            "sender_name": row.get("sender_name", ""),
            "reasons": " | ".join(reasons),
            "risk": "HIGH" if threat >= 2 or credential else "MEDIUM",
        })

    return pd.DataFrame(records) if records else _empty_result([
        "message_id", "threat_signals", "channel", "timestamp", "sender_domain", "sender_name", "reasons", "risk"
    ])


# ============================================================
# DETECTOR 6 - CREDENTIAL HARVESTING
# ============================================================

def detect_credential_harvesting(messages):
    messages, _ = _prepare_messages(messages, optional_columns=[
        "message_id", "message_text", "claimed_identity", "claimed_role",
        "claimed_organisation", "sender_domain", "sender_name", "channel", "timestamp"
    ])
    if messages is None:
        return _empty_result(["message_id", "credential_signals", "redirect_signals", "channel", "timestamp", "reasons", "risk"])
    messages = ensure_message_id(messages)
    records = []

    for _, row in messages.iterrows():
        body = _message_body(row)
        text = _message_context(row)
        credential = _count_non_negated_matches(body, CREDENTIAL_PATTERN)
        redirect = _count_matches(body, REDIRECT_PATTERN)
        explicit_request = _is_explicit_credential_request(body)
        blocking = _verification_blocking_count(body)
        dangerous_level, dangerous_reason = _dangerous_action(body)

        # A mere mention of OTP/password is not enough. The message
        # must request the secret, or combine a redirect with a clear
        # identity/social-engineering context.
        identity = bool(_text_of(row, "claimed_identity") or _text_of(row, "claimed_role"))
        qualifying = explicit_request or (credential and redirect and identity)
        if not qualifying:
            continue

        reasons = [f"Sensitive credential/secret reference detected ({credential} indicator(s))"]
        if explicit_request:
            reasons.append("Message explicitly asks the recipient to provide a credential or verification secret")
        if redirect:
            reasons.append(f"Redirect/link signal detected ({redirect} indicator(s))")
        if blocking:
            reasons.append("Verification-blocking language detected")
        if dangerous_level == "DANGEROUS":
            reasons.append(dangerous_reason)

        records.append({
            "message_id": row.get("message_id"),
            "credential_signals": credential,
            "redirect_signals": redirect,
            "verification_blocking_signals": blocking,
            "dangerous_action": dangerous_level,
            "channel": row.get("channel", ""),
            "timestamp": row.get("timestamp", ""),
            "sender_domain": row.get("sender_domain", ""),
            "sender_name": row.get("sender_name", ""),
            "reasons": " | ".join(dict.fromkeys(reasons)),
            "risk": "HIGH" if (explicit_request and (redirect or blocking or credential >= 2)) else "MEDIUM",
        })

    return pd.DataFrame(records) if records else _empty_result([
        "message_id", "credential_signals", "redirect_signals", "verification_blocking_signals",
        "dangerous_action", "channel", "timestamp", "sender_domain", "sender_name", "reasons", "risk"
    ])


# ============================================================
# CAMPAIGN CLUSTERING
# ============================================================

def summarise_campaigns(detector_frames):
    labelled = []
    for frame, threat_name in detector_frames or []:
        if frame is None or frame.empty or "message_id" not in frame.columns:
            continue
        part = frame.copy()
        part["threat"] = threat_name
        labelled.append(part)

    if not labelled:
        return pd.DataFrame(columns=["campaign_key", "message_count", "threats"])

    combined = pd.concat(labelled, ignore_index=True, sort=False)
    if "sender_domain" not in combined.columns:
        return pd.DataFrame(columns=["campaign_key", "message_count", "threats"])

    domains = combined.dropna(subset=["sender_domain"])
    domains = domains[domains["sender_domain"].astype(str).str.strip() != ""]
    if domains.empty:
        return pd.DataFrame(columns=["campaign_key", "message_count", "threats"])

    campaigns = []
    for domain, group in domains.groupby("sender_domain"):
        campaigns.append({
            "campaign_key": str(domain),
            "message_count": int(group["message_id"].nunique()),
            "threats": ", ".join(sorted(set(group["threat"].astype(str))))
        })

    return pd.DataFrame(campaigns).sort_values("message_count", ascending=False).reset_index(drop=True)
