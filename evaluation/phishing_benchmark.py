"""CyberGuard remote phishing benchmark.

Benchmarks the same Hugging Face Space used by CyberGuard's frontend.
The benchmark does not modify the live application.

Dataset:
- ealvaradob/phishing-dataset historical test.json from the 94efbff commit
- Labels: 1 = phishing, 0 = benign
- A deterministic balanced sample is selected from the test set.
- The test split is pinned to a historical commit because test.json is no longer
  present on the dataset repository main branch.

Inference:
- Hugging Face Space: saswatpatra/cyberguard_phishing
- Gradio endpoint: /analyze_message

This produces CyberGuard-specific evaluation metrics for the deployed
phishing inference service. It is not a claim about the training data or
about production-wide accuracy.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
EVALUATION_DIR = Path(__file__).resolve().parent
CACHE_DIR = EVALUATION_DIR / ".cache"
DATASET_PATH = CACHE_DIR / "phishing_test.json"
REPORT_PATH = EVALUATION_DIR / "phishing_benchmark_report.json"

DATASET_COMMIT = "94efbffcb4e26305d8d68d507a39c8065c6d97e3"
DATASET_URL = (
    "https://huggingface.co/datasets/ealvaradob/phishing-dataset/"
    f"resolve/{DATASET_COMMIT}/test.json"
)
SPACE_ID = "saswatpatra/cyberguard_phishing"
SPACE_HOST = "https://saswatpatra-cyberguard-phishing.hf.space"
API_NAME = "/analyze_message"


def http_request(url: str, *, method: str = "GET", payload: Any = None, timeout: int = 120):
    headers = {"User-Agent": "CyberGuard-Phishing-Benchmark/1.0"}
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode("utf-8")
    request = Request(url, data=data, headers=headers, method=method)
    with urlopen(request, timeout=timeout) as response:
        return response.status, response.read()


def load_dataset() -> list[dict[str, Any]]:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    if not DATASET_PATH.exists():
        print("Downloading public phishing test set...")
        _, content = http_request(DATASET_URL, timeout=300)
        DATASET_PATH.write_bytes(content)

    raw = json.loads(DATASET_PATH.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        if "data" in raw:
            raw = raw["data"]
        elif "test" in raw:
            raw = raw["test"]

    if not isinstance(raw, list):
        raise ValueError("Unexpected phishing test-set format.")

    cases = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        text = str(item.get("text", "")).strip()
        label = item.get("label")
        if not text or label not in (0, 1, "0", "1"):
            continue
        cases.append({
            "case_id": f"PHISH-{index + 1:05d}",
            "text": text,
            "expected_label": int(label),
        })
    return cases


def select_balanced_cases(cases: list[dict[str, Any]], sample_size: int, seed: int):
    rng = random.Random(seed)
    benign = [case for case in cases if case["expected_label"] == 0]
    phishing = [case for case in cases if case["expected_label"] == 1]
    per_class = sample_size // 2
    if per_class < 1:
        raise ValueError("sample_size must be at least 2.")
    if len(benign) < per_class or len(phishing) < per_class:
        raise ValueError(
            f"Not enough balanced test cases: benign={len(benign)}, phishing={len(phishing)}, "
            f"requested per class={per_class}."
        )
    selected = rng.sample(benign, per_class) + rng.sample(phishing, per_class)
    rng.shuffle(selected)
    return selected


def parse_sse(raw: bytes):
    text = raw.decode("utf-8", errors="replace")
    data_lines = []
    for line in text.splitlines():
        if line.startswith("data:"):
            data_lines.append(line[5:].strip())
    if not data_lines:
        raise RuntimeError(f"No SSE data returned by Hugging Face: {text[:1000]}")

    for item in reversed(data_lines):
        if item in {"null", ""}:
            continue
        try:
            return json.loads(item)
        except json.JSONDecodeError:
            continue
    raise RuntimeError(f"Could not decode Hugging Face SSE response: {data_lines[-1][:1000]}")


def call_space(text: str, retries: int = 3):
    submit_url = f"{SPACE_HOST}/gradio_api/call/analyze_message"
    last_error = None

    for attempt in range(retries):
        try:
            _, content = http_request(
                submit_url,
                method="POST",
                payload={"data": [text]},
                timeout=120,
            )
            submission = json.loads(content.decode("utf-8"))
            event_id = submission.get("event_id")
            if not event_id:
                raise RuntimeError(f"No event_id returned: {submission}")

            result_url = f"{SPACE_HOST}/gradio_api/call/analyze_message/{event_id}"
            deadline = time.time() + 180
            while time.time() < deadline:
                _, result_bytes = http_request(result_url, timeout=120)
                result = parse_sse(result_bytes)
                if result is not None:
                    return result
                time.sleep(1)
        except (HTTPError, URLError, TimeoutError, OSError, RuntimeError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt < retries - 1:
                time.sleep(2 ** attempt)

    raise RuntimeError(f"Hugging Face phishing inference failed: {last_error}")


def flatten(value: Any):
    output = []
    if value is None:
        return output
    if isinstance(value, (str, int, float, bool)):
        return [str(value)]
    if isinstance(value, list):
        for item in value:
            output.extend(flatten(item))
        return output
    if isinstance(value, dict):
        for key, item in value.items():
            output.append(f"{key}: {item}" if isinstance(item, (str, int, float, bool)) else str(key))
            output.extend(flatten(item))
    return output


def extract_prediction(value: Any, *, allow_numeric: bool = False):
    """Return True=phishing, False=benign, None=unresolved."""
    if isinstance(value, dict):
        preferred_keys = (
            "model_prediction", "is_phishing", "is_phishing_message",
            "prediction", "label", "classification", "class",
            "threat", "verdict", "result",
        )
        for key in preferred_keys:
            if key in value:
                result = extract_prediction(value[key], allow_numeric=True)
                if result is not None:
                    return result
        for key, item in value.items():
            if key.lower() in {
                "confidence", "score", "risk_score", "indicator_score",
                "model_confidence",
            }:
                continue
            result = extract_prediction(item)
            if result is not None:
                return result
        return None

    if isinstance(value, list):
        for item in value:
            result = extract_prediction(item)
            if result is not None:
                return result
        return None

    if isinstance(value, bool):
        return value

    if allow_numeric and isinstance(value, (int, float)) and not isinstance(value, bool):
        if value == 1:
            return True
        if value == 0:
            return False

    text = str(value).strip().lower()
    text = re.sub(r"\s+", " ", text)

    if allow_numeric and text in {"1", "0"}:
        return text == "1"

    # Check explicit benign phrases first so "not phishing" is not treated as phishing.
    benign_patterns = (
        r"\bnot phishing\b",
        r"\bnon[- ]phishing\b",
        r"\bbenign\b",
        r"\bsafe\b",
        r"\blegitimate\b",
        r"\bclean\b",
        r"\bno threat\b",
        r"\bno immediate threat\b",
        r"\bham\b",
    )
    phishing_patterns = (
        r"\bphishing\b",
        r"\bphish\b",
        r"\bmalicious\b",
        r"\bfraudulent\b",
        r"\bscam\b",
        r"\bsmishing\b",
        r"\bunsafe\b",
    )

    if any(re.search(pattern, text) for pattern in benign_patterns):
        return False
    if any(re.search(pattern, text) for pattern in phishing_patterns):
        return True
    return None


def binary_metrics(expected: list[int], predicted: list[int]):
    tp = sum(e == 1 and p == 1 for e, p in zip(expected, predicted))
    tn = sum(e == 0 and p == 0 for e, p in zip(expected, predicted))
    fp = sum(e == 0 and p == 1 for e, p in zip(expected, predicted))
    fn = sum(e == 1 and p == 0 for e, p in zip(expected, predicted))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / len(expected) if expected else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {
        "samples": len(expected),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
    }


def run(sample_size: int, seed: int):
    cases = select_balanced_cases(load_dataset(), sample_size, seed)
    expected = []
    predicted = []
    unresolved = []
    case_results = []

    for number, case in enumerate(cases, 1):
        print(f"[{number}/{len(cases)}] analysing {case['case_id']}...")
        raw = call_space(case["text"])
        prediction = extract_prediction(raw)
        expected_label = int(case["expected_label"])

        case_results.append({
            "case_id": case["case_id"],
            "expected_label": "phishing" if expected_label else "benign",
            "predicted_label": (
                "phishing" if prediction is True
                else "benign" if prediction is False
                else "unresolved"
            ),
            "raw_result": raw,
        })

        if prediction is None:
            unresolved.append(case["case_id"])
            continue
        expected.append(expected_label)
        predicted.append(1 if prediction else 0)

    report = {
        "module": "Phishing",
        "evaluation_type": "remote labelled test-set benchmark",
        "space": SPACE_ID,
        "endpoint": API_NAME,
        "dataset": "ealvaradob/phishing-dataset/test.json",
        "dataset_source": DATASET_URL,
        "dataset_commit": DATASET_COMMIT,
        "sample_size_requested": sample_size,
        "scored_samples": len(expected),
        "seed": seed,
        "binary_metrics": binary_metrics(expected, predicted),
        "unresolved_cases": unresolved,
        "unresolved_count": len(unresolved),
        "warning": (
            "CyberGuard-specific remote evaluation of the configured Hugging Face inference service. "
            "The dataset is public and external; these results are not an independent production certification."
        ),
        "case_results": case_results,
    }
    REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description="Benchmark CyberGuard phishing inference via Hugging Face.")
    parser.add_argument("--samples", type=int, default=100, help="Balanced total test cases (default: 100).")
    parser.add_argument("--seed", type=int, default=42, help="Deterministic sampling seed (default: 42).")
    args = parser.parse_args()

    report = run(args.samples, args.seed)
    print(json.dumps(report, indent=2))
    print(f"\nSaved report: {REPORT_PATH}")


if __name__ == "__main__":
    main()
