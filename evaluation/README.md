# CyberGuard Evaluation Suite

This folder contains evaluation and regression-validation tools for the three CyberGuard detection modules currently exposed by the project.

## Evaluation files

```text
evaluation/
├── README.md
├── README_phishing_benchmark.md
├── benchmark.py
├── phishing_benchmark.py
├── ato_evaluation_cases.json
└── latest_benchmark_report.json
```

`phishing_benchmark_report.json` is generated after the phishing benchmark is run and is intentionally not treated as a hand-authored source file.

## 1. Digital Impersonation

Uses the existing labelled dataset:

```text
cyberguard_impersonation_messages.csv
```

The 20 `borderline` records are reported separately. Only the `malicious` and `benign` records are used for binary classification metrics.

Reported metrics:

- Accuracy
- Precision
- Recall
- F1
- False-positive rate
- TP / TN / FP / FN
- Borderline flag count
- Risk-level distribution

Current repository validation result:

- Accuracy: **85.00%**
- Precision: **98.51%**
- Recall: **82.50%**
- F1: **89.80%**
- False-positive rate: **5.00%**
- TP: 66
- TN: 19
- FP: 1
- FN: 14

These are CyberGuard engineering-validation results against the bundled labelled dataset. They are not independent production certification.

## 2. Account Takeover

Uses the frozen controlled evaluation set:

```text
evaluation/ato_evaluation_cases.json
```

**Do not modify this file for normal development or benchmark runs.** It is the source of truth for the current ATO regression benchmark.

The dataset contains 24 controlled scenarios:

- 12 malicious scenarios
- 12 benign control scenarios
- 2 cases for each of the six ATO detectors

The six detector scenarios are:

1. Multiple Failed Login Attempts
2. Password Spraying
3. Unusual Login Location
4. Unknown / New Device
5. Suspicious Session Activity
6. Sudden Account Behaviour Change

Current controlled-validation result:

- Accuracy: **100.00%**
- Precision: **100.00%**
- Recall: **100.00%**
- F1: **100.00%**
- False-positive rate: **0.00%**
- TP: 12
- TN: 12
- FP: 0
- FN: 0

These ATO cases are authored synthetic scenarios designed for engineering validation and regression testing. They must not be presented as independent real-world production accuracy.

## 3. Phishing

Phishing is evaluated separately because the trained CyberGuard phishing model is deployed in the Hugging Face Space:

```text
saswatpatra/cyberguard_phishing
```

The benchmark sends labelled messages through the same `/analyze_message` Gradio endpoint used by the CyberGuard frontend. Hugging Face documents Gradio Spaces as callable APIs and exposes their endpoint schema through the Space API documentation. urlHugging Face Spaces API documentationhttps://huggingface.co/docs/hub/en/spaces-api-endpoints

### Dataset used

The benchmark uses the historical `test.json` split from `ealvaradob/phishing-dataset`, pinned to commit:

```text
94efbffcb4e26305d8d68d507a39c8065c6d97e3
```

The historical commit contains the `test.json` file. The current `main` branch no longer contains that file, so the benchmark pins the commit instead of relying on a moving URL. The dataset defines `text` and `label`, with `1 = phishing` and `0 = benign`. citeturn1search8turn1search6

This is a reproducible remote benchmark of the deployed CyberGuard inference service. It should only be described as a held-out evaluation if the model training process did not include this test split.

### Default run

```bash
python evaluation/phishing_benchmark.py --samples 100
```

The sample is deterministic and balanced:

- 50 benign
- 50 phishing
- random seed: `42`

The benchmark reports:

- Accuracy
- Precision
- Recall
- F1
- False-positive rate
- TP / TN / FP / FN
- unresolved cases

The generated report is:

```text
evaluation/phishing_benchmark_report.json
```

### Unified run

```bash
python evaluation/benchmark.py
```

This runs:

1. Digital Impersonation
2. Account Takeover
3. Phishing remote benchmark

For local modules only:

```bash
python evaluation/benchmark.py --skip-phishing
```

The unified report is written to:

```text
evaluation/latest_benchmark_report.json
```

If the remote phishing service is temporarily unavailable, the unified runner records the phishing benchmark as failed instead of inventing or reusing metrics from an older run.

## Important interpretation rules

- Do **not** average the three modules into one overall CyberGuard accuracy.
- Do **not** present the published metrics of an underlying pretrained model as CyberGuard benchmark results.
- Phishing metrics produced by `phishing_benchmark.py` describe the deployed `saswatpatra/cyberguard_phishing` inference service on the selected public test sample.
- ATO metrics describe controlled synthetic engineering validation.
- Digital Impersonation metrics describe the bundled CyberGuard engineering dataset.
- The evaluation code does not change production detection logic, risk scoring, APIs, frontend behaviour, or production datasets.
