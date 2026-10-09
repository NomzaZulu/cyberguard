# CyberGuard 🛡️

**AI-powered cyber threat intelligence dashboard** — phishing message / website / QR analysis plus two full behavioural detection engines: **Account Takeover (ATO)** with per-user risk scoring, and **Digital Impersonation** with per-message risk scoring.

Built as a single organisation-security platform: a static frontend plus two Python serverless APIs on Vercel, with phishing inference remaining on the connected Hugging Face Space.

---

## Live Demo

**https://cyberguard-sigma-woad.vercel.app**

The dashboard and Python APIs are served from the same deployment. Phishing inference is connected directly to the configured Hugging Face Space.

---

## Features

### 1. Phishing Analysis (message / URL / QR)
- **Message analysis** — paste any SMS, email or chat text and get a phishing verdict.
- **Website analysis** — submit a URL for reputation and phishing checks.
- **QR code analysis** — upload a QR image and decode it to check the embedded link.
- Powered by the Gradio inference Space [`saswatpatra/cyberguard_phishing`](https://huggingface.co/spaces/saswatpatra/cyberguard_phishing), called client-side from the browser through `@gradio/client`.

### 2. Account Takeover Detection Engine
Six behavioural detectors run over login telemetry, fused by a weighted risk engine into a single score and a `LOW` / `MEDIUM` / `HIGH` verdict per user.

| # | Detector | What it catches |
|---|----------|-----------------|
| 1 | Multiple Failed Login Attempts | Password guessing / brute force from a single source |
| 2 | Password Spraying | One password tried against many accounts from one IP |
| 3 | Unusual Login Location | Login from a location outside the user's normal baseline |
| 4 | Unknown / New Device | First-seen device, or a device outside the user's known set |
| 5 | Suspicious Session Activity | Session actions inconsistent with a normal login flow |
| 6 | Sudden Account Behaviour Change | Abrupt shift in a user's usual location, device or login pattern |

**Risk engine**
- Weighted detector contributions, plus bonuses for **evidence volume**, **repetition** and **cross-detector correlation**.
- Thresholds: `LOW < 30 ≤ MEDIUM < 70 ≤ HIGH`.
- Every flagged user is returned with exact detector evidence, an attack type, confidence, recommended response actions, and a unified incident record. Password-spraying evidence is attributed to each targeted account.

### 3. Digital Impersonation Detection Engine
Six content detectors run over reported messages (SMS, email, chat, social, QR), fused into a single score and a `LOW` / `MEDIUM` / `HIGH` verdict per message.

| # | Detector | What it catches |
|---|----------|-----------------|
| 1 | Authority Impersonation | A sender posing as police, tax, court, government or a regulator |
| 2 | Executive Impersonation | A sender posing as a CEO, director, HR, payroll or university authority |
| 3 | Brand Impersonation | A message claiming a bank or brand, or sent from a lookalike domain |
| 4 | Urgency & Pressure Tactics | Coercive deadlines and "do not tell anyone" instructions that block verification |
| 5 | Threatening Or Extortion Language | Legal, policing or financial threats used to force compliance |
| 6 | Credential Harvesting Via Impersonation | A trusted-identity claim combined with a request for an OTP, PIN, password or card details |

**Risk engine**
- Weighted detector contributions plus bonuses for **evidence volume**, **repetition** and **cross-detector correlation** — an identity + pressure + credential-request chain scores highest.
- Thresholds: `LOW < 30 ≤ MEDIUM < 70 ≤ HIGH`.
- Returns each flagged message with the detectors that fired, human-readable evidence, attack category, confidence, recommended response actions, the original message text, and a **campaign view** grouping detections by sender infrastructure.

---

## Tech Stack

| Layer | Choice |
|-------|--------|
| Frontend | Vanilla HTML / CSS / JS (no build step) |
| ATO engine | Python 3, pandas, custom risk scoring |
| Impersonation engine | Python 3, pandas, word-boundary keyword matching, custom risk scoring |
| API (ATO) | FastAPI, deployed as a Vercel Python serverless function |
| API (impersonation) | FastAPI, deployed as a Vercel Python serverless function |
| Shared incident layer | Python `security_core/unified_incident.py` |
| Hosting | Vercel (static + Python serverless APIs) |

---

## Project Structure

```
.
├── index.html                     # Static dashboard shell
├── style.css                      # Dashboard styling
├── script.js                      # Frontend logic + Gradio client
├── vercel.json                    # Serverless function config (framework preset disabled)
├── requirements.txt               # Python deps for the ATO + impersonation functions
├── package.json                   # Project metadata
│
├── api/
│   ├── account_takeover.py        # FastAPI app (POST /api/account_takeover)
│   └── digital_impersonation.py   # FastAPI app (POST /api/digital_impersonation)
│
├── account_takeover/
│   ├── account_takeover_engine.py # The six detectors
│   ├── account_takeover_service.py# Pipeline: DataFrames -> JSON report
│   └── risk_engine.py             # Scoring, bonuses, thresholds
│
├── digital_impersonation/
│   ├── digital_impersonation_engine.py # The six detectors + campaign grouping
│   ├── digital_impersonation_service.py# Pipeline: DataFrames -> JSON report
│   └── risk_engine.py             # Scoring, bonuses, thresholds
│
├── cyberguard_login_events.csv        # Sample ATO telemetry
├── cyberguard_organisation_profiles.csv # Sample ATO user baselines
├── cyberguard_impersonation_messages.csv # 120-message labelled evaluation set
├── security_core/                 # Shared incident/risk conventions
├── evaluation/                    # Local benchmark tooling
├── test_api_local.py              # ATO API regression harness
├── test_impersonation_local.py    # Impersonation API regression harness
├── test_digital_impersonation_stress.py # Impersonation stress suite
└── test_adversarial_inputs.py     # Cross-engine adversarial regression suite
```

---

## Unified Incident Model

The three visible modules remain separate detection engines, but their outputs are normalised into a shared incident model containing:

- incident ID and timestamp
- module and severity
- risk score and confidence
- attack type
- source and target
- organisation context
- evidence
- recommended response actions

This lets the dashboard, history and PDF reports use one security vocabulary without collapsing the three detection categories into one detector.

## Validation

Run the local benchmark with:

```bash
python evaluation/benchmark.py
```

Run adversarial regression checks with:

```bash
python test_adversarial_inputs.py
```

The benchmark currently evaluates the 120-message impersonation dataset and reports precision/recall/F1 against its malicious/benign labels, while borderline samples are reported separately.

---

## API

### `POST /api/account_takeover`

```jsonc
{
  "events": [
    {
      "timestamp": "2026-10-03T10:00:00",
      "user_id": "user001",
      "login_status": "failed",
      "ip_address": "203.0.113.10",
      "location": "Unknown City",
      "device": "Chrome-Windows",
      "session_action": "login_failed"
    }
  ],
  "profiles": [
    {
      "user_id": "user001",
      "normal_locations": "Bhubaneswar",
      "known_devices": "Edge-Windows"
    }
  ]
}
```

`profiles` is optional. Response:

```jsonc
{
  "success": true,
  "type": "account_takeover",
  "result": {
    "summary": { "users_analyzed": 6, "accounts_flagged": 6, "high_risk": 2, "medium_risk": 4, "detection_events": 15 },
    "users": [ /* per-user risk, verdict, detectors, evidence */ ]
  }
}
```

`GET /api/account_takeover` returns a health check. Empty `events` returns `400`.

### `POST /api/digital_impersonation`

```jsonc
{
  "messages": [
    {
      "timestamp": "2026-10-03T09:30:00",
      "message_id": "msg002",
      "channel": "email",
      "sender_domain": "sbi-netbanking-alert.xyz",
      "claimed_identity": "SBI Customer Care",
      "claimed_role": "security officer",
      "claimed_organisation": "State Bank of India",
      "message_text": "Your account will be suspended today. Confirm your OTP and net banking password.",
      "context": "vendor reported a bank phishing email"
    }
  ]
}
```

Response:

```jsonc
{
  "success": true,
  "type": "digital_impersonation",
  "result": {
    "summary": { "messages_analyzed": 6, "messages_flagged": 6, "high_risk": 6, "medium_risk": 0, "low_risk": 0, "detection_events": 21, "detector_types": 6 },
    "messages": [ /* per-message risk, verdict, detectors, reasons, original text */ ],
    "detections": [ /* individual detector events */ ],
    "campaigns": [ /* detections grouped by sender infrastructure */ ]
  }
}
```

`GET /api/digital_impersonation` returns a health check. Empty `messages` returns `400`.

### CSV columns

**Events** — `timestamp` *(required)*, `user_id` *(required)*, `login_status`, `ip_address`, `location`, `device`, `session_action`. Optional `event_id` / `session_id` are synthesised when absent.

**Profiles** — `user_id`, `normal_locations`, `known_devices`.

### Impersonation CSV columns

**Messages** — `message_id` *(required)*, `channel`, `sender_name`, `sender_domain`, `claimed_identity`, `claimed_role`, `claimed_organisation`, `message_text`, `context`, `timestamp`. `message_id` is synthesised when absent; the engine also reads the body plus the claimed identity/role/organisation together, so a scam described only in the identity field is still detected.

---

## Running Locally

### ATO engine only (CLI)

```bash
cd CyberGuard-main
python -m account_takeover.account_takeover_engine
```

Reads the two sample CSVs from the project root and prints every detector's output.

### Impersonation engine only (CLI)

```bash
cd CyberGuard-main
python -m digital_impersonation.digital_impersonation_engine
```

Runs a built-in sample through all six impersonation detectors.

### ATO API

```bash
cd CyberGuard-main
pip install -r requirements.txt
python -m uvicorn api.account_takeover:app --port 8000
```

### Impersonation API

```bash
cd CyberGuard-main
python -m uvicorn api.digital_impersonation:app --port 8000
```

### Static frontend

```bash
cd CyberGuard-main
python -m http.server 5173
```

Open `http://localhost:5173`. The dashboard calls `/api/account_takeover` and `/api/digital_impersonation` on its own origin, so serve the frontend and the API from the same origin (or use the CORS-enabled APIs on `http://localhost:8000`).

### Regression harnesses

```bash
cd CyberGuard-main
python test_api_local.py            # Account takeover
python test_impersonation_local.py  # Digital impersonation
```

Both exit `0` when every case passes. The ATO harness covers the demo scenario, missing optional columns, empty payload, both path aliases and CORS preflight. The impersonation harness additionally asserts that **legitimate business messages are never classified high risk** and that repeated sender infrastructure is clustered into one campaign.

---

## Deploying to Vercel

1. From the project folder, authenticate the CLI once: `npx vercel login`.
2. Deploy: `npx vercel deploy --prod --yes` (or `vercel --prod` against a linked GitHub repo).
3. No environment variables are required — the Hugging Face Space is public. If you ever make it private or gated, add an `HF_TOKEN` variable (a read token for that Space); the serverless proxy connects anonymously until then.
4. In the Vercel dashboard turn **off Deployment Protection** (Settings → Deployment Protection) so the URL is open to anyone — otherwise visitors hit a Vercel login wall.

`vercel.json` pins `"framework": null` so Vercel treats the repo as a plain static + serverless project: `index.html`, `script.js` and `style.css` are served statically, and anything under `api/` becomes a serverless function. That means `/api/account_takeover` and `/api/analyze` resolve with no rewrite rules.

Both endpoints live on the same domain as the frontend, so no CORS configuration or client-side URL change is needed in production.