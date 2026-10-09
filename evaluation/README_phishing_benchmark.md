# CyberGuard Phishing Benchmark

## Purpose

This benchmark evaluates the **deployed CyberGuard phishing detection service**, not a generic published model-card score.

The benchmark calls the same Hugging Face Space and endpoint used by the CyberGuard frontend:

- Space: `saswatpatra/cyberguard_phishing`
- Endpoint: `/analyze_message`
- Inference host: `https://saswatpatra-cyberguard-phishing.hf.space`

Hugging Face documents that Gradio Spaces can be called programmatically and exposes the endpoint schema through the Space API. urlHugging Face Spaces API documentationhttps://huggingface.co/docs/hub/en/spaces-api-endpoints

## Dataset

The benchmark uses the historical `test.json` split from:

```text
ealvaradob/phishing-dataset
```

The file is pinned to commit:

```text
94efbffcb4e26305d8d68d507a39c8065c6d97e3
```

This pin is intentional. `test.json` existed in that historical commit but is no longer present on the dataset repository's current `main` branch. The dataset uses `text` and `label`, with `1 = phishing` and `0 = benign`. citeturn1search8turn1search6

The benchmark downloads the test file into:

```text
evaluation/.cache/phishing_test.json
```

The cache is temporary and should **not** be committed to GitHub.

## Sampling

Default run:

```bash
python evaluation/phishing_benchmark.py --samples 100
```

The selection is:

- 100 total cases
- 50 benign
- 50 phishing
- deterministic random seed: `42`

A larger run can be requested, for example:

```bash
python evaluation/phishing_benchmark.py --samples 200
```

## Inference flow

```text
Public labelled test cases
          ↓
Balanced deterministic sample
          ↓
CyberGuard Hugging Face Space
saswatpatra/cyberguard_phishing
          ↓
/analyze_message
          ↓
Deployed CyberGuard phishing inference
          ↓
Prediction extraction
          ↓
TP / TN / FP / FN
          ↓
Accuracy / Precision / Recall / F1 / FPR
```

The benchmark includes the raw inference response for each scored case in the generated JSON report so the result can be audited.

## Output

The report is written to:

```text
evaluation/phishing_benchmark_report.json
```

The unified evaluation runner also includes the phishing result in:

```text
evaluation/latest_benchmark_report.json
```

## Interpretation

These are **CyberGuard-specific remote inference evaluation results**.

They are not:

- published model-card metrics
- a claim of production-wide accuracy
- an independent certification of the model
- a combined CyberGuard accuracy across all three modules

The historical test split should only be described as a held-out test set if the model-training process did not include those records. If the model was trained on this exact test split, use a genuinely external labelled dataset for the final independent evaluation instead.

## Unified suite

Run everything:

```bash
python evaluation/benchmark.py
```

Run only the local Digital Impersonation and ATO evaluations:

```bash
python evaluation/benchmark.py --skip-phishing
```
