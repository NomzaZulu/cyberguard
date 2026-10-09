"""
CyberGuard regression harness for the Digital Impersonation module.

Run with:  python test_impersonation_local.py

Exercises the impersonation pipeline through the FastAPI app
exactly like the frontend does.
"""

import json
import sys

sys.path.insert(0, ".")

from fastapi.testclient import TestClient  # noqa: E402

from api.digital_impersonation import app  # noqa: E402


# Exact demo payload from script.js -> loadImpersonationDemo()
# Default organisation profile: Acme Corporation / acme-corp.com.
# test_sender_logic.mjs fails if script.js and this payload drift apart.
DEMO_MESSAGES = [
    {"timestamp": "2026-10-03T09:00:00", "message_id": "msg001", "channel": "sms", "sender_name": "+911234567890", "sender_domain": "+911234567890", "claimed_identity": "Acme Corporation IT Helpdesk", "claimed_role": "IT administrator", "claimed_organisation": "Acme Corporation", "message_text": "URGENT notice from Acme Corporation IT: your network password will expire today. Confirm your OTP and current password on the verification form immediately or your account will be blocked. Do not share this with anyone.", "context": "reported by the Acme Corporation service desk"},
    {"timestamp": "2026-10-03T09:30:00", "message_id": "msg002", "channel": "email", "sender_name": "hr@hr-update-portal.top", "sender_domain": "hr-update-portal.top", "claimed_identity": "Acme Corporation Payroll", "claimed_role": "hr manager", "claimed_organisation": "Acme Corporation", "message_text": "Attention Acme Corporation employees. Your salary revision is approved. Share your bank account number and OTP on this secure payroll form to update your records. Click the link below to submit details.", "context": "forwarded to the Acme Corporation IT inbox by staff"},
    {"timestamp": "2026-10-03T10:00:00", "message_id": "msg003", "channel": "email", "sender_name": "ceo@acme-corp.com", "sender_domain": "acme-corp.com", "claimed_identity": "Acme Corporation CEO Office", "claimed_role": "CEO", "claimed_organisation": "Acme Corporation", "message_text": "This is the Acme Corporation CEO. We have a confidential board meeting today. I need you to change the vendor bank details immediately and transfer the advance payment before midnight. Do not discuss this with the finance department.", "context": "reported by the Acme Corporation finance team"},
    {"timestamp": "2026-10-03T10:30:00", "message_id": "msg004", "channel": "sms", "sender_name": "+919876543210", "sender_domain": "+919876543210", "claimed_identity": "Acme Corporation Legal & Compliance", "claimed_role": "legal officer", "claimed_organisation": "Acme Corporation", "message_text": "URGENT notice from Acme Corporation Legal & Compliance: a case has been registered against you for money laundering. Your Acme Corporation bank account will be frozen within 24 hours and a penalty of 50000 rupees has been imposed. Do not call anyone to verify.", "context": "received by Acme Corporation staff on a company-issued mobile"},
    {"timestamp": "2026-10-03T11:00:00", "message_id": "msg005", "channel": "email", "sender_name": "accounts@invoice-approval.top", "sender_domain": "invoice-approval.top", "claimed_identity": "Acme Corporation Accounts", "claimed_role": "finance officer", "claimed_organisation": "Acme Corporation", "message_text": "URGENT: the Acme Corporation accounts department requires the vendor bank details changed today. Transfer the advance payment to the new beneficiary before midnight and confirm your OTP to authorise. Do not discuss this with anyone.", "context": "reported by the Acme Corporation accounts team"},
    {"timestamp": "2026-10-03T11:30:00", "message_id": "msg006", "channel": "sms", "sender_name": "+919812345678", "sender_domain": "+919812345678", "claimed_identity": "Acme Corporation Security Team", "claimed_role": "security officer", "claimed_organisation": "Acme Corporation", "message_text": "Your Acme Corporation account is suspended. Confirm your OTP immediately on the verification link or your access will be blocked. Click here to verify now. Do not share this code with anyone.", "context": "flagged by Acme Corporation IT security"},
]

# Legitimate business messages that must never be classified high risk.
BENIGN_MESSAGES = [
    {"timestamp": "2026-10-03T09:00:00", "message_id": "ok1", "channel": "email", "sender_name": "Ravi Kumar", "sender_domain": "acme-corp.com", "claimed_identity": "Ravi Kumar", "claimed_role": "Accounts Manager", "claimed_organisation": "Acme Corporation", "message_text": "Hi team, the quarterly vendor reconciliation meeting is scheduled for Thursday at 11 AM in Room 4. Please bring the approved invoices. Regards, Ravi", "context": "internal business email"},
    {"timestamp": "2026-10-03T09:30:00", "message_id": "ok2", "channel": "email", "sender_name": "Academic Office", "sender_domain": "university.edu.in", "claimed_identity": "Examination Cell", "claimed_role": "Registrar", "claimed_organisation": "University", "message_text": "The examination schedule for the semester has been published on the university portal. Students may download their hall tickets from the official site.", "context": "genuine notice from the university"},
    {"timestamp": "2026-10-03T10:00:00", "message_id": "ok3", "channel": "sms", "sender_name": "Delivery", "sender_domain": "", "claimed_identity": "City Courier", "claimed_role": "Delivery Agent", "claimed_organisation": "City Courier", "message_text": "Your parcel is out for delivery today. Please keep your phone available. No action is required.", "context": "ordinary delivery notification"},
]


client = TestClient(app)

failures = []


print("== health ==")
r = client.get("/")
print("status:", r.status_code, json.dumps(r.json())[:140])
if r.status_code != 200:
    failures.append("health check did not return 200")


# The demo dataset must describe this organisation, not unrelated
# third-party brands: every row claims the organisation and names it in
# the reporting context.
org_names = {msg.get("claimed_organisation") for msg in DEMO_MESSAGES}
if org_names != {"Acme Corporation"}:
    failures.append(f"demo rows must all claim the organisation: {org_names}")

if not all("Acme Corporation" in msg.get("context", "") for msg in DEMO_MESSAGES):
    failures.append("every demo context must name the organisation")


print("\n== demo analysis (frontend demo payload) ==")
r = client.post("/", json={"messages": DEMO_MESSAGES})
print("status:", r.status_code)
if r.status_code != 200:
    print(r.text[:2000])
    sys.exit(1)

summary = r.json()["result"]["summary"]
print("summary:", json.dumps(summary))
for msg in r.json()["result"]["messages"]:
    print("  message:", msg["message_id"], msg["risk_level"], msg["risk_score"], msg["detectors_triggered"])

if summary["messages_analyzed"] != 6:
    failures.append("expected 6 messages analysed")
if summary["high_risk"] < 5:
    failures.append("expected at least 5 high-risk messages in the demo scenario")
if summary["detector_types"] != 6:
    failures.append("expected 6 detector types")

# Senders are email addresses or phone numbers, so every reported
# sender must reach the campaign view (domains and numbers cluster).
demo_campaigns = r.json()["result"]["campaigns"]
print("campaigns:", json.dumps(demo_campaigns))
if not demo_campaigns:
    failures.append("expected sender campaigns for the email/phone demo senders")

# The sender address must be echoed back so the dashboard and PDF
# report can show who actually sent the reported message.
demo_messages = r.json()["result"]["messages"]
if any(not msg.get("sender_name") for msg in demo_messages):
    failures.append("every analysed message must carry its sender address")


print("\n== benign messages must not be high risk ==")
r = client.post("/", json={"messages": BENIGN_MESSAGES})
print("status:", r.status_code)
benign_summary = r.json()["result"]["summary"]
print("summary:", json.dumps(benign_summary))
for msg in r.json()["result"]["messages"]:
    print("  message:", msg["message_id"], msg["risk_level"], msg["risk_score"], msg["detectors_triggered"])
if benign_summary["high_risk"] != 0:
    failures.append("benign messages must not be classified high risk")


print("\n== edge case: empty messages ==")
r = client.post("/", json={"messages": []})
print("status:", r.status_code, r.json().get("detail", "<ok>"))
if r.status_code != 400:
    failures.append("expected 400 for empty messages")


print("\n== edge case: only message_id column ==")
r = client.post("/", json={"messages": [{"message_id": "bare1"}, {"message_id": "bare2"}]})
print("status:", r.status_code)
if r.status_code != 200:
    print(r.text[:2000])
    failures.append("expected 200 for a message_id-only payload")
else:
    print("summary:", json.dumps(r.json()["result"]["summary"]))

print("\n== edge case: NO message_id column must still be analysed ==")
# A CSV that omits message_id must not silently return zero
# detections: identifiers are synthesised from row position.
no_id = [
    {"channel": "sms", "claimed_organisation": "State Bank of India", "message_text": "URGENT confirm your OTP now or legal action will be taken"},
    {"channel": "sms", "claimed_organisation": "Delhi Police", "message_text": "URGENT government notice, your bank account will be frozen. Do not tell anyone."},
]
r = client.post("/", json={"messages": no_id})
print("status:", r.status_code)
if r.status_code != 200:
    print(r.text[:2000])
    failures.append("expected 200 when message_id is absent")
else:
    body = r.json()["result"]
    print("summary:", json.dumps(body["summary"]))
    for msg in body["messages"]:
        print("  message:", msg["message_id"], msg["risk_level"], msg["risk_score"])
    if body["summary"]["messages_flagged"] == 0:
        failures.append("malicious messages must still be flagged when message_id is absent")
    if body["summary"]["messages_analyzed"] != 2:
        failures.append("expected 2 messages analysed when message_id is absent")

print("\n== edge case: blank message_id must not collide ==")
partial_id = [
    {"message_id": "real1", "channel": "sms", "claimed_organisation": "Delhi Police", "message_text": "URGENT government notice, account will be frozen"},
    {"message_id": "", "channel": "sms", "claimed_organisation": "Income Tax Department", "message_text": "URGENT tax notice, legal action will be taken"},
]
r = client.post("/", json={"messages": partial_id})
print("status:", r.status_code)
body = r.json()["result"]
ids = [msg["message_id"] for msg in body["messages"]]
print("identifiers:", ids)
if len(set(ids)) != len(ids):
    failures.append(f"synthesised identifiers collided: {ids}")
if body["summary"]["messages_flagged"] != 2:
    failures.append("expected both messages flagged when one identifier is blank")


print("\n== path aliases ==")
r = client.post("/api/digital_impersonation", json={"messages": DEMO_MESSAGES})
print("POST:", r.status_code, "flagged:", r.json()["result"]["summary"]["messages_flagged"] if r.status_code == 200 else r.text[:300])
if r.status_code != 200:
    failures.append("POST path alias failed")

r = client.get("/api/digital_impersonation")
print("GET :", r.status_code, r.json().get("status"))
if r.status_code != 200:
    failures.append("GET path alias failed")


print("\n== campaign clustering ==")
clustered = [
    {"timestamp": "2026-10-03T09:00:00", "message_id": "c1", "channel": "sms", "sender_domain": "evil-spoof.xyz", "claimed_organisation": "State Bank of India", "message_text": "Urgent: confirm your OTP and click here to update your KYC now."},
    {"timestamp": "2026-10-03T09:05:00", "message_id": "c2", "channel": "sms", "sender_domain": "evil-spoof.xyz", "claimed_organisation": "State Bank of India", "message_text": "Final warning: your account will be blocked. Send the code immediately to avoid legal action."},
]
r = client.post("/", json={"messages": clustered})
print("status:", r.status_code)
campaigns = r.json()["result"]["campaigns"]
print("campaigns:", json.dumps(campaigns))
if not campaigns or campaigns[0]["message_count"] != 2:
    failures.append("expected one campaign covering 2 messages from the same domain")


print("\n" + "=" * 60)

if failures:
    print("FAILED CHECKS:")
    for failure in failures:
        print(" -", failure)
    sys.exit(1)

print("ALL CHECKS PASSED")
