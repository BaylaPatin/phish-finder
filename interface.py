"""
interface.py — Phish Finder shared contracts

This file defines the dataclasses and function signatures each team member must
implement.  Import from here rather than defining your own types so the pieces
plug together without friction.

"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


# ---------------------------------------------------------------------------
# Shared data types
# ---------------------------------------------------------------------------

@dataclass
class ClassifierResult:
    """Output from DistilBERT classifier."""

    label: str          # "phish" | "benign"
    confidence: float   # 0.0 – 1.0
    # Optional extras (fill in if available; leave None otherwise)
    raw_logits: list[float] | None = None


@dataclass
class URLSignal:
    """Risk data for a single URL extracted from a message."""

    url: str
    virustotal_malicious: int = 0   # number of VT engines that flagged it
    virustotal_total: int = 0       # total VT engines checked
    google_safe_browsing_hit: bool = False
    phishtank_hit: bool = False
    score: float = 0.0              # 0.0 (clean) – 1.0 (definite phish)


@dataclass
class URLAnalysisResult:
    """Output from URL module."""

    urls_found: list[str]
    signals: list[URLSignal]
    aggregate_score: float  # 0.0 – 1.0 (worst URL drives this)


@dataclass
class HeaderAnalysisResult:
    """Output from header module."""

    spf_pass: bool | None       # None = record absent / unresolvable
    dkim_pass: bool | None
    dmarc_pass: bool | None
    from_reply_to_mismatch: bool
    suspicious_domains: list[str]   # domains that look spoofed / lookalike
    score: float                    # 0.0 – 1.0


@dataclass
class Verdict:
    """Final output from agent pipeline."""

    is_phish: bool
    confidence: float               # 0.0 – 1.0
    explanation: str                # human-readable summary
    classifier_result: ClassifierResult
    url_result: URLAnalysisResult
    header_result: HeaderAnalysisResult
    iocs: list[str] = field(default_factory=list)   # URLs / domains / IPs


@dataclass
class InboxScanResult:
    """Output from post-confirmation inbox scanner."""

    related_message_ids: list[str]  # message IDs of similar suspicious mails
    matched_subjects: list[str]
    matched_domains: list[str]
    matched_senders: list[str]


@dataclass
class IOCSubmissionResult:
    """Status of IOC submissions to threat-intel platforms."""

    otx_submitted: bool
    threatfox_submitted: bool
    phishtank_submitted: bool
    errors: list[str] = field(default_factory=list)



class AgentPipeline(Protocol):
    """
    Person 3 wires together the classifier and signal modules, handles the
    user review step, drives the inbox scanner, and submits IOCs.
    """

    def build_verdict(
        self,
        classifier_result: ClassifierResult,
        url_result: URLAnalysisResult,
        header_result: HeaderAnalysisResult,
    ) -> Verdict:
        """
        Combine outputs from Person 1 and Person 2 into a final verdict with
        an explanation string.

        Args:
            classifier_result: From MLClassifier.classify_message()
            url_result:        From SignalAnalyzer.analyze_urls()
            header_result:     From SignalAnalyzer.analyze_headers()

        Returns:
            Verdict — is_phish flag, confidence, and human-readable explanation.
        """
        ...

    def run_inbox_scan(
        self,
        verdict: Verdict,
        inbox_messages: list[dict],
    ) -> InboxScanResult:
        """
        After the user confirms a phishing verdict, scan the inbox for related
        messages using subject similarity, domain overlap, and sender matching.

        Args:
            verdict:         The confirmed Verdict.
            inbox_messages:  List of message dicts with at minimum the keys:
                             "id", "subject", "from", "body".

        Returns:
            InboxScanResult listing related message IDs and matched indicators.
        """
        ...

    def submit_iocs(self, verdict: Verdict) -> IOCSubmissionResult:
        """
        Extract IOCs from the confirmed verdict and submit them to OTX,
        ThreatFox, and PhishTank.

        Args:
            verdict: A confirmed phishing Verdict (is_phish must be True).

        Returns:
            IOCSubmissionResult indicating which platforms accepted the submission.
        """
        ...


# ---------------------------------------------------------------------------
# Quick integration smoke-test (run: python interface.py)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Stub implementations so each person can verify their outputs
    # slot into the shared types without running the full pipeline.

    dummy_classifier = ClassifierResult(label="phish", confidence=0.93)

    dummy_url = URLAnalysisResult(
        urls_found=["http://evil-bank.com/login"],
        signals=[
            URLSignal(
                url="http://evil-bank.com/login",
                virustotal_malicious=12,
                virustotal_total=72,
                google_safe_browsing_hit=True,
                phishtank_hit=True,
                score=0.95,
            )
        ],
        aggregate_score=0.95,
    )

    dummy_header = HeaderAnalysisResult(
        spf_pass=False,
        dkim_pass=None,
        dmarc_pass=False,
        from_reply_to_mismatch=True,
        suspicious_domains=["evil-bank.com"],
        score=0.80,
    )

    dummy_verdict = Verdict(
        is_phish=True,
        confidence=0.92,
        explanation="DistilBERT confidence 93 %, URL flagged by VirusTotal and PhishTank, SPF/DMARC fail, From/Reply-To mismatch.",
        classifier_result=dummy_classifier,
        url_result=dummy_url,
        header_result=dummy_header,
        iocs=["http://evil-bank.com/login", "evil-bank.com"],
    )

    print("Smoke test passed — all dataclasses construct without errors.")
    print(f"  Verdict: is_phish={dummy_verdict.is_phish}, confidence={dummy_verdict.confidence}")
    print(f"  IOCs:    {dummy_verdict.iocs}")
