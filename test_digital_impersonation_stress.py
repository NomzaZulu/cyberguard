"""Focused false-positive / false-negative stress tests for Digital Impersonation."""

import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from digital_impersonation.digital_impersonation_service import analyze_digital_impersonation


def row(message_id, sender, domain, identity, role, text, channel="email"):
    return {
        "message_id": message_id,
        "channel": channel,
        "sender_name": sender,
        "sender_domain": domain,
        "claimed_identity": identity,
        "claimed_role": role,
        "claimed_organisation": "Acme Corporation",
        "message_text": text,
        "context": "Digital Impersonation stress-test case",
    }


ATTACKS = [
    row("a01", "ceo@acme-secure.top", "acme-secure.top", "Acme Corporation CEO", "CEO", "I am the CEO. Urgent supplier payment required immediately. Send the beneficiary confirmation and keep this confidential."),
    row("a02", "hr@acme-payroll.xyz", "acme-payroll.xyz", "Acme Corporation HR", "HR Manager", "Your salary account needs verification. Enter your employee ID, password and OTP now or payroll will be delayed."),
    row("a03", "security@acme-login.top", "acme-login.top", "Acme Corporation Security Team", "Security Officer", "Your account will be blocked. Click here and confirm your password and OTP immediately. Do not call the helpdesk."),
    row("a04", "notice@gmail.com", "gmail.com", "Income Tax Department", "Tax Officer", "Final notice. Send your PAN and verification code today to avoid legal action."),
    row("a05", "finance@invoice-approval.xyz", "invoice-approval.xyz", "Acme Corporation Accounts", "Finance Officer", "Change the vendor beneficiary and transfer the advance payment before midnight. Confirm the OTP."),
    row("a06", "+919900000001", "+919900000001", "Delhi Police Cyber Cell", "Cyber Officer", "Your account is linked to a fraud case. Send the OTP immediately to prevent arrest." , "sms"),
    row("a07", "director@acme-board.top", "acme-board.top", "Acme Corporation Director", "Director", "I am the Director. Purchase gift cards immediately and send me the codes. I cannot take calls."),
    row("a08", "support@acme-verify.xyz", "acme-verify.xyz", "Acme Corporation Support", "Support Team", "Your support case expires today. Click the link and enter your login credentials and verification code."),
    row("a09", "legal@acme-notice.top", "acme-notice.top", "Acme Corporation Legal", "Legal Officer", "A case has been registered. Failure to respond today will result in account suspension. Do not contact the department."),
    row("a10", "cfo@acme-finance.xyz", "acme-finance.xyz", "Acme Corporation CFO", "CFO", "Urgent confidential request: transfer the invoice amount to the new beneficiary before the board meeting."),
    row("a11", "it@acme-password.top", "acme-password.top", "Acme Corporation IT Helpdesk", "IT Administrator", "Your password expires today. Verify your password and OTP on the secure form immediately."),
    row("a12", "+919900000002", "+919900000002", "Acme Corporation Payroll", "Payroll Administrator", "Reply with your bank account number and verification code before 5 PM or salary processing will be delayed.", "sms"),
    row("a13", "tax@acme-tax-alert.xyz", "acme-tax-alert.xyz", "Income Tax Department", "Tax Officer", "Submit your PAN and OTP immediately. Do not call anyone to verify this notice."),
    row("a14", "procurement@acme-vendor.top", "acme-vendor.top", "Acme Corporation Procurement", "Procurement Head", "The supplier bank details changed. Update the beneficiary and release the payment today. Keep this confidential."),
    row("a15", "security@acme-alert.xyz", "acme-alert.xyz", "Acme Corporation Security Team", "Security Officer", "Suspicious login detected. Verify your password at the link below or access will be blocked."),
    row("a16", "ceo.office@acme-board.xyz", "acme-board.xyz", "Acme Corporation CEO Office", "CEO", "This is the CEO. Please buy gift cards and send the codes before the client call. Do not discuss this request."),
    row("a17", "registrar@acme-campus.top", "acme-campus.top", "Acme Corporation Administration", "Registrar", "Your access is suspended. Upload your ID and password through the verification portal immediately."),
    row("a18", "finance@acme-invoice.xyz", "acme-invoice.xyz", "Acme Corporation Finance", "Finance Officer", "Urgent invoice request. Send the transaction code and confirm the new beneficiary before midnight."),
    row("a19", "cybercell@gmail.com", "gmail.com", "Police Cyber Cell", "Cyber Officer", "A fraud investigation has been opened. Send your verification code now or a warrant may be issued."),
    row("a20", "hr@acme-benefits.top", "acme-benefits.top", "Acme Corporation HR", "HR Manager", "Click the payroll verification link and enter your password and OTP immediately."),
]

BENIGN = [
    row("b01", "ceo@acme-corp.com", "acme-corp.com", "Acme Corporation CEO", "CEO", "I am sharing the agenda for tomorrow's board meeting. No action is required today."),
    row("b02", "security@acme-corp.com", "acme-corp.com", "Acme Corporation Security Team", "Security Officer", "Security awareness reminder: we will never ask for passwords, OTPs or PINs. Report suspicious messages through the official helpdesk."),
    row("b03", "hr@acme-corp.com", "acme-corp.com", "Acme Corporation HR", "HR Manager", "Benefits enrollment closes Friday. Use the official HR portal. No credentials are requested by email."),
    row("b04", "finance@acme-corp.com", "acme-corp.com", "Acme Corporation Finance", "Finance Officer", "The monthly reimbursement cycle closes Friday. Review your submitted claims in the official finance portal."),
    row("b05", "it@acme-corp.com", "acme-corp.com", "Acme Corporation IT Helpdesk", "IT Administrator", "Planned maintenance will take place tonight. No employee action is required."),
    row("b06", "registrar@acme-corp.com", "acme-corp.com", "Acme Corporation Administration", "Registrar", "The annual compliance calendar has been published. Please review the dates on the official intranet."),
    row("b07", "accounts@acme-corp.com", "acme-corp.com", "Acme Corporation Accounts", "Accounts Manager", "The quarterly vendor reconciliation meeting is scheduled for Thursday. Please bring the approved invoices."),
    row("b08", "security@acme-corp.com", "acme-corp.com", "Acme Corporation Security Team", "Security Officer", "We detected a login from a new device. If this was you, no action is required. Otherwise contact the official helpdesk."),
    row("b09", "legal@acme-corp.com", "acme-corp.com", "Acme Corporation Legal", "Legal Officer", "The updated travel policy is available on the official intranet. Please review it before your next trip."),
    row("b10", "board@acme-corp.com", "acme-corp.com", "Acme Corporation Board Office", "Board Secretary", "The board meeting begins at 10 AM tomorrow. The finance team should attend."),
    row("b11", "support@acme-corp.com", "acme-corp.com", "Acme Corporation Support", "Support Team", "Your support ticket has been updated. View the status from the official support portal."),
    row("b12", "compliance@acme-corp.com", "acme-corp.com", "Acme Corporation Compliance", "Compliance Officer", "Annual compliance training is due Friday. Complete the course through the official learning portal."),
    row("b13", "procurement@acme-corp.com", "acme-corp.com", "Acme Corporation Procurement", "Procurement Head", "The approved supplier list has been updated in the procurement system. Use the normal purchase-order workflow."),
    row("b14", "admin@acme-corp.com", "acme-corp.com", "Acme Corporation Administration", "Administrator", "The office access-card maintenance schedule is available on the intranet. No credentials are requested."),
    row("b15", "legal@acme-corp.com", "acme-corp.com", "Acme Corporation Legal", "Legal Officer", "The legal team completed its review of the vendor agreement. The signed copy is available in the repository."),
    row("b16", "accounts@acme-corp.com", "acme-corp.com", "Acme Corporation Accounts", "Accounts Manager", "Please review the approved invoice register before Friday. Contact accounts through the internal directory."),
    row("b17", "hr@acme-corp.com", "acme-corp.com", "Acme Corporation HR", "HR Manager", "The employee handbook has been updated. Review the new leave policy on the internal HR portal."),
    row("b18", "finance@acme-corp.com", "acme-corp.com", "Acme Corporation Finance", "Finance Officer", "The approved expense policy is available on the internal finance portal. No payment is requested in this message."),
    row("b19", "ceo@acme-corp.com", "acme-corp.com", "Acme Corporation CEO", "CEO", "Thank you for the work this quarter. Please join the company town hall next Tuesday."),
    row("b20", "security@acme-corp.com", "acme-corp.com", "Acme Corporation Security Team", "Security Officer", "We will never request your OTP, password or PIN. Report suspicious messages to the official security address."),
]


def main():
    attack_result = analyze_digital_impersonation(pd.DataFrame(ATTACKS))
    benign_result = analyze_digital_impersonation(pd.DataFrame(BENIGN))

    attack_messages = attack_result["messages"]
    benign_messages = benign_result["messages"]

    attack_high = sum(m["risk_level"] == "HIGH" for m in attack_messages)
    benign_high = sum(m["risk_level"] == "HIGH" for m in benign_messages)

    print("Attack cases:", len(ATTACKS), "flagged:", len(attack_messages), "high:", attack_high)
    print("Benign cases:", len(BENIGN), "flagged:", len(benign_messages), "high:", benign_high)

    failures = []
    if attack_high < 18:
        failures.append(f"expected at least 18/20 attack cases HIGH, got {attack_high}")
    if benign_high != 0:
        failures.append(f"expected 0 benign HIGH classifications, got {benign_high}")
    if not all("attack_category" in m and "confidence" in m and "confidence_score" in m for m in attack_messages):
        failures.append("risk reports must expose attack category and confidence")
    if not any(m.get("attack_category") == "Business Email Compromise" for m in attack_messages):
        failures.append("expected BEC classification in attack set")
    if not any(m.get("dangerous_action") == "DANGEROUS" for m in attack_messages):
        failures.append("expected dangerous-action classification")
    if not any(m.get("sender_authenticity", 100) < 45 for m in attack_messages):
        failures.append("expected low sender-authenticity evidence")

    if failures:
        print("FAILED CHECKS:")
        for failure in failures:
            print(" -", failure)
        raise SystemExit(1)

    print("STRESS TESTS PASSED")


if __name__ == "__main__":
    main()
