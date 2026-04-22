"""
test_pipeline.py — Smoke-test the full agent_pipeline + inbox_scanner using the
trained DistilBERT model in ./phish_model_best.

Wires:
    - TrainedClassifier (loads phish_model_best/) as the MLClassifier
    - StubAnalyzer (regex-only URL/header heuristics) as the SignalAnalyzer
      since Person 2's real module isn't in the repo yet.

Run:
    python test_pipeline.py              # non-interactive, auto-confirm phish
    python test_pipeline.py --interactive
"""

from __future__ import annotations

import argparse
import os
import re

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from agent_pipeline import PhishFinderPipeline
from interface import (
    ClassifierResult,
    HeaderAnalysisResult,
    IOCSubmissionResult,
    URLAnalysisResult,
    URLSignal,
    Verdict,
)

MODEL_DIR = os.path.join(os.path.dirname(__file__), "phish_model_best")


class TrainedClassifier:
    """Wraps the fine-tuned DistilBERT model as an MLClassifier."""

    def __init__(self, model_dir: str = MODEL_DIR) -> None:
        self.tokenizer = AutoTokenizer.from_pretrained(model_dir)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_dir)
        self.model.eval()
        # id2label from training: 0=LEGITIMATE, 1=PHISHING
        self.id2label = self.model.config.id2label

    def classify_message(self, text: str) -> ClassifierResult:
        inputs = self.tokenizer(
            text,
            truncation=True,
            padding="max_length",
            max_length=256,
            return_tensors="pt",
        )
        with torch.no_grad():
            logits = self.model(**inputs).logits[0]
        probs = torch.softmax(logits, dim=-1).tolist()
        pred_id = int(torch.argmax(logits).item())
        raw_label = self.id2label[pred_id].lower()
        # interface contract uses "phish" / "benign"
        label = "phish" if raw_label.startswith("phish") else "benign"
        return ClassifierResult(
            label=label,
            confidence=float(probs[pred_id]),
            raw_logits=logits.tolist(),
        )


# ---------------------------------------------------------------------------
# Stub signal analyzer — just enough to exercise the pipeline end-to-end
# ---------------------------------------------------------------------------

_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_SUSPICIOUS_TLDS = {"zip", "xyz", "top", "click", "tk", "cf", "ga", "ml"}
_SUSPICIOUS_HINTS = ("login", "verify", "secure", "account", "update", "bank")


class StubAnalyzer:
    """Regex-only placeholder for Person 2's real SignalAnalyzer."""

    def analyze_urls(self, text: str) -> URLAnalysisResult:
        urls = _URL_RE.findall(text or "")
        signals: list[URLSignal] = []
        for url in urls:
            score = 0.0
            lower = url.lower()
            tld = lower.rsplit(".", 1)[-1].split("/")[0]
            if tld in _SUSPICIOUS_TLDS:
                score += 0.5
            if any(h in lower for h in _SUSPICIOUS_HINTS):
                score += 0.3
            if re.search(r"\d+\.\d+\.\d+\.\d+", lower):
                score += 0.4
            signals.append(URLSignal(url=url, score=min(score, 1.0)))
        aggregate = max((s.score for s in signals), default=0.0)
        return URLAnalysisResult(
            urls_found=urls, signals=signals, aggregate_score=aggregate
        )

    def analyze_headers(self, raw_headers) -> HeaderAnalysisResult:
        headers = self._parse(raw_headers)

        def auth(key: str) -> bool | None:
            val = headers.get("authentication-results", "").lower()
            if f"{key}=pass" in val:
                return True
            if f"{key}=fail" in val:
                return False
            return None

        spf = auth("spf")
        dkim = auth("dkim")
        dmarc = auth("dmarc")

        from_dom = self._domain(headers.get("from", ""))
        reply_dom = self._domain(headers.get("reply-to", ""))
        mismatch = bool(from_dom and reply_dom and from_dom != reply_dom)

        suspicious = []
        if from_dom and any(c.isdigit() for c in from_dom.split(".")[0]):
            suspicious.append(from_dom)

        score = 0.0
        for passed in (spf, dkim, dmarc):
            if passed is False:
                score += 0.25
        if mismatch:
            score += 0.25
        if suspicious:
            score += 0.2

        return HeaderAnalysisResult(
            spf_pass=spf,
            dkim_pass=dkim,
            dmarc_pass=dmarc,
            from_reply_to_mismatch=mismatch,
            suspicious_domains=suspicious,
            score=min(score, 1.0),
        )

    @staticmethod
    def _parse(raw) -> dict[str, str]:
        if isinstance(raw, dict):
            return {k.lower(): v for k, v in raw.items()}
        out: dict[str, str] = {}
        for line in (raw or "").splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                out[k.strip().lower()] = v.strip()
        return out

    @staticmethod
    def _domain(addr: str) -> str:
        m = re.search(r"@([A-Za-z0-9\-\.]+)", addr or "")
        return m.group(1).lower() if m else ""


# ---------------------------------------------------------------------------
# Sample messages
# ---------------------------------------------------------------------------

PHISH_BODY = (
    "Dear customer, your Chase account has been suspended. "
    "Please verify your identity immediately at "
    "http://chase-secure-login.zip/verify or your account will be closed."
)
PHISH_HEADERS = (
    "From: Chase Support <support@chase-secure-login.zip>\n"
    "Reply-To: billing@random-mailer.top\n"
    "Subject: URGENT: Account suspended\n"
    "Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail\n"
)

BENIGN_BODY = (
    "Hey team, attaching the Q3 planning doc for tomorrow's meeting. "
    "Let me know if you have comments. Thanks!"
)
BENIGN_HEADERS = (
    "From: Alice <alice@company.com>\n"
    "Reply-To: alice@company.com\n"
    "Subject: Q3 planning doc\n"
    "Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass\n"
)

INBOX = [
    {
        "id": "msg-001",
        "subject": "URGENT: Account suspended",
        "from": "Chase Support <support@chase-secure-login.zip>",
        "body": PHISH_BODY,
    },
    {
        "id": "msg-002",
        "subject": "URGENT: Account suspended!!",
        "from": "Chase <noreply@chase-secure-login.zip>",
        "body": "Click http://chase-secure-login.zip/verify now.",
    },
    {
        "id": "msg-003",
        "subject": "Lunch Friday?",
        "from": "bob@company.com",
        "body": "Wanna grab lunch Friday?",
    },
    {
        "id": "msg-004",
        "subject": "Re: Account suspended",
        "from": "billing@random-mailer.top",
        "body": "Please reply with your password to restore access.",
    },
]


def run_case(pipeline: PhishFinderPipeline, name: str, body: str, headers: str,
             inbox: list[dict] | None) -> None:
    print("\n" + "#" * 70)
    print(f"# CASE: {name}")
    print("#" * 70)
    outcome = pipeline.process_message(body, headers, inbox=inbox)
    v = outcome.verdict
    print(f"\n→ is_phish={v.is_phish}  confidence={v.confidence}")
    print(f"→ classifier: {v.classifier_result.label} "
          f"@ {v.classifier_result.confidence:.3f}")
    print(f"→ url aggregate: {v.url_result.aggregate_score:.3f} "
          f"({len(v.url_result.urls_found)} urls)")
    print(f"→ header score:  {v.header_result.score:.3f}")
    print(f"→ iocs: {v.iocs}")
    print(f"→ user_confirmed: {outcome.user_confirmed}")
    if outcome.inbox_scan:
        s = outcome.inbox_scan
        print(f"→ inbox matches: {s.related_message_ids}")
        print(f"  matched_subjects: {s.matched_subjects}")
        print(f"  matched_domains:  {s.matched_domains}")
        print(f"  matched_senders:  {s.matched_senders}")
    if outcome.ioc_submission:
        i = outcome.ioc_submission
        print(f"→ submissions: otx={i.otx_submitted} "
              f"threatfox={i.threatfox_submitted} "
              f"phishtank={i.phishtank_submitted}")
        if i.errors:
            print(f"  errors: {i.errors}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--interactive", action="store_true",
                        help="Prompt for y/n at the user-review step.")
    parser.add_argument("--submit", action="store_true",
                        help="Actually submit IOCs to OTX/ThreatFox/PhishTank. "
                             "OFF by default so tests don't hit real endpoints.")
    args = parser.parse_args()

    print(f"Loading model from {MODEL_DIR} ...")
    classifier = TrainedClassifier()
    analyzer = StubAnalyzer()
    pipeline = PhishFinderPipeline(
        classifier, analyzer, interactive=args.interactive
    )
    if not args.submit:
        def _no_submit(verdict: Verdict) -> IOCSubmissionResult:
            return IOCSubmissionResult(
                otx_submitted=False,
                threatfox_submitted=False,
                phishtank_submitted=False,
                errors=["(submission disabled in test harness; pass --submit to enable)"],
            )
        pipeline.submit_iocs = _no_submit  # type: ignore[method-assign]

    run_case(pipeline, "Phishing sample", PHISH_BODY, PHISH_HEADERS, INBOX)
    run_case(pipeline, "Benign sample", BENIGN_BODY, BENIGN_HEADERS, INBOX)


if __name__ == "__main__":
    main()
