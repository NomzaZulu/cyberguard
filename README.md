# CyberGuard

**CyberGuard is an organisation-focused cybersecurity dashboard** that brings together three separate detection modules: phishing analysis, account-takeover risk analysis, and digital-impersonation analysis. It presents findings, risk levels, evidence, and suggested response actions in one interface.

> **Important scope note:** CyberGuard is a prototype. Its modules use different detection approaches and evaluation datasets. It should not be described as a fully autonomous security operations centre, a universal threat detector, or a system with one overall accuracy score.

## Demo

**Dashboard:** https://cyberguardvaultx.vercel.app/

The dashboard is a static frontend hosted on Vercel. The Account Takeover and Digital Impersonation APIs are Python serverless functions on the same deployment. Phishing inference is sent to the configured public Hugging Face Space, `saswatpatra/cyberguard_phishing`.

Availability of the deployed website does not by itself guarantee that every API or the external inference Space is reachable at all times.

## What CyberGuard does

### 1. Phishing analysis

The frontend connects to the `saswatpatra/cyberguard_phishing` Gradio Space for these analysis modes:

- **Message analysis:** analyse pasted message text, such as an email, SMS, or chat message.
- **Website analysis:** submit a website URL for analysis.
- **QR analysis:** upload a QR-code image for decoding and analysis of its content.

The configured Gradio API names are `/analyze_message`, `/analyze_website`, and `/scan_qr`. The trained phishing inference service is hosted separately from this repository; its model architecture, training details, and training metrics should only be stated when supported by the model's own training records.

### 2. Account Takeover (ATO) analysis

The ATO module analyses authentication-event data against user profile baselines. It uses six behavioural detectors:

1. Multiple failed login attempts
2. Password spraying
3. Unusual login location
4. Unknown or new device
5. Suspicious session activity
6. Sudden account-behaviour change

The engine combines detector evidence into a risk score and returns risk classifications, explanations/evidence, and recommended response actions. This module is a **custom behavioural and rule-based risk engine**, not a separately trained machine-learning model.

### 3. Digital Impersonation analysis

The Digital Impersonation module analyses reported messages and their sender/claimed-identity context. It uses six contextual detectors:

1. Authority impersonation
2. Executive impersonation
3. Brand impersonation
4. Urgency and pressure tactics
5. Threatening or extortion language
6. Credential harvesting through impersonation

Its contextual rules and weighted risk engine produce per-message risk assessments and supporting indicators. The service can also group related detections into campaign views. This module is a **custom rule-based/contextual engine**, not a separately trained machine-learning model.

## How results are produced

The modules remain separate because they analyse different kinds of input:

- **Phishing:** remote inference through the configured Hugging Face Space.
- **Account Takeover:** behavioural analysis of login events and user baselines.
- **Digital Impersonation:** contextual analysis of messages, sender information, and claimed identities.

Their outputs are presented through a common dashboard and incident/reporting format. Risk scores from different modules should not be assumed to be directly comparable, and their evaluation metrics should not be averaged into a single CyberGuard accuracy figure.

## Technology stack

| Area | Technology |
|---|---|
| Frontend | HTML, CSS, vanilla JavaScript |
| Phishing inference | Hugging Face Spaces / Gradio client |
| ATO and impersonation APIs | Python, FastAPI, pandas |
| Deployment | Vercel static hosting and Python serverless functions |
| Reporting | Dashboard incident views and browser-generated PDF reporting |
| Evaluation | Python benchmark scripts and labelled/synthetic test cases |

No frontend build step is required for the static dashboard.

## Project structure

```text
.
├── index.html
├── style.css
├── script.js
├── pdf-report.js
├── vercel.json
├── package.json
├── requirements.txt
├── api/
│   ├── account_takeover.py
│   └── digital_impersonation.py
├── account_takeover/
│   ├── account_takeover_engine.py
│   ├── account_takeover_service.py
│   └── risk_engine.py
├── digital_impersonation/
│   ├── digital_impersonation_engine.py
│   ├── digital_impersonation_service.py
│   └── risk_engine.py
├── security_core/
│   └── unified_incident.py
├── cyberguard_login_events.csv
├── cyberguard_organisation_profiles.csv
├── cyberguard_impersonation_messages.csv
├── evaluation/
└── test_*.py / test_*.mjs
```

The CSV files are sample/demo data. Do not treat them as live organisational telemetry or as proof of real-world detection performance.

## Evaluation and testing

Evaluation is split by module because the data sources and methods differ.

- **Digital Impersonation:** `cyberguard_impersonation_messages.csv` contains labelled messages used by the bundled benchmark. The current benchmark scores the malicious and benign labels separately from the borderline cases. Results are engineering validation on this project dataset, not independent certification.
- **Account Takeover:** `evaluation/ato_evaluation_cases.json` is a controlled synthetic scenario set covering the six detectors. Its metrics measure how the engine handles those authored scenarios; they are not real-world production accuracy. Keep this dataset unchanged when reproducing the current benchmark.
- **Phishing:** `evaluation/phishing_benchmark.py` is intended to send labelled samples through the same remote Space used by the frontend. A valid accessible dataset source and an available Space/API are required. Do not report phishing metrics unless the run completes successfully and produces a report.

Run the two local engine evaluations:

```bash
python evaluation/benchmark.py --skip-phishing
```

Attempt the remote phishing benchmark separately:

```bash
python evaluation/phishing_benchmark.py --samples 100
```

Run the unified benchmark, including the remote phishing step:

```bash
python evaluation/benchmark.py
```

The scripts write their generated report files under `evaluation/`. Review the report's status and warnings before quoting any metrics. Do not combine module metrics into a single score.

### Regression tests

Run the available local tests from the project root:

```bash
python test_api_local.py
python test_impersonation_local.py
python test_digital_impersonation_stress.py
python test_adversarial_inputs.py
```

These tests exercise the code paths represented by each test file. Passing local tests does not establish production availability or real-world detection accuracy.

## API reference

The two Python APIs expose health checks and analysis endpoints.

### Account Takeover

- `GET /api/account_takeover` — health check
- `POST /api/account_takeover` — analyse authentication events and optional user profiles

The POST request accepts an `events` array. Each event should include a `timestamp` and `user_id`; fields such as `login_status`, `ip_address`, `location`, `device`, and `session_action` provide additional evidence. An optional `profiles` array can provide each user's normal locations and known devices.

### Digital Impersonation

- `GET /api/digital_impersonation` — health check
- `POST /api/digital_impersonation` — analyse reported messages

The POST request accepts a `messages` array. Useful fields include `message_id`, `channel`, `sender_name`, `sender_domain`, `claimed_identity`, `claimed_role`, `claimed_organisation`, `message_text`, `context`, and `timestamp`.

The API handlers also define a root route (`/`) for health and POST analysis. For exact request/response fields, refer to the corresponding API files and service implementations.

## Run the Python APIs locally

Use Python 3.10 or newer, then install the dependencies:

```bash
python -m venv .venv
```

Activate the virtual environment, then run:

```bash
pip install -r requirements.txt
```

Start the APIs in separate terminals:

```bash
python -m uvicorn api.account_takeover:app --port 8000
```

```bash
python -m uvicorn api.digital_impersonation:app --port 8001
```

The local API health checks are available at `http://127.0.0.1:8000/api/account_takeover` and `http://127.0.0.1:8001/api/digital_impersonation` respectively. The static frontend uses same-origin `/api/...` paths, so simply serving it on another port with `python -m http.server` will **not** automatically connect it to these separate API ports. Use the integrated Vercel deployment for the full application unless you configure a local reverse proxy or matching same-origin setup.

## Deployment notes

The Vercel configuration declares two Python serverless functions:

- `api/account_takeover.py`
- `api/digital_impersonation.py`

The static frontend is served from the project root. The phishing module calls the public Hugging Face Space from the browser using the Gradio client; it is not served by either Python API in this repository. The current project does not define an `/api/analyze` phishing proxy, so deployment instructions should not refer to one.

## Limitations

- Phishing inference depends on an external Hugging Face Space and its availability.
- ATO and Digital Impersonation use custom rule/context-based logic; they are not independently trained ML models.
- Bundled datasets are demo/evaluation inputs, not live feeds.
- Evaluation results depend on the specific dataset and test cases. They do not establish production-wide accuracy.
- This prototype provides analysis and recommendations; do not imply it automatically blocks accounts, quarantines email, or performs other response actions unless such integration is implemented and verified.

## License

See the repository's existing license file.
