
from __future__ import annotations

from dataclasses import dataclass

from interface import (
    AgentPipeline,
    ClassifierResult,
    HeaderAnalysisResult,
    InboxScanResult,
    IOCSubmissionResult,
    MLClassifier,
    SignalAnalyzer,
    URLAnalysisResult,
    Verdict,
)

from inbox_scanner import run_inbox_scan as _run_inbox_scan
from ioc_submission import submit_iocs as _submit_iocs
from user_review import prompt_user_review
from verdict import build_verdict as _build_verdict


@dataclass
class PipelineOutcome:
    """Everything produced during a full run, for logging / downstream UI."""

    verdict: Verdict
    user_confirmed: bool
    inbox_scan: InboxScanResult | None = None
    ioc_submission: IOCSubmissionResult | None = None


class PhishFinderPipeline(AgentPipeline):
    def __init__(
        self,
        classifier: MLClassifier,
        analyzer: SignalAnalyzer,
        *,
        interactive: bool = True,
    ) -> None:
        self.classifier = classifier
        self.analyzer = analyzer
        self.interactive = interactive

    # ----- AgentPipeline protocol methods ---------------------------------

    def build_verdict(
        self,
        classifier_result: ClassifierResult,
        url_result: URLAnalysisResult,
        header_result: HeaderAnalysisResult,
    ) -> Verdict:
        return _build_verdict(classifier_result, url_result, header_result)

    def run_inbox_scan(
        self,
        verdict: Verdict,
        inbox_messages: list[dict],
    ) -> InboxScanResult:
        return _run_inbox_scan(verdict, inbox_messages)

    def submit_iocs(self, verdict: Verdict) -> IOCSubmissionResult:
        return _submit_iocs(verdict)

    # ----- Full end-to-end flow -------------------------------------------

    def process_message(
        self,
        body: str,
        headers: str | dict,
        inbox: list[dict] | None = None,
    ) -> PipelineOutcome:
        """
        Run the full pipeline on one message.

        Args:
            body:    Raw message body text.
            headers: Raw RFC 2822 header block or pre-parsed dict.
            inbox:   Optional list of inbox messages for the post-confirmation
                     scan.  The first entry should be the message being
                     analyzed (used as the reference for similarity/sender
                     matching); if not provided, the scan is skipped.

        Returns:
            PipelineOutcome with verdict + any post-confirmation results.
        """
        clf = self.classifier.classify_message(body)
        url = self.analyzer.analyze_urls(body)
        hdr = self.analyzer.analyze_headers(headers)

        verdict = self.build_verdict(clf, url, hdr)

        confirmed = False
        if self.interactive:
            confirmed = prompt_user_review(verdict)
        else:
            confirmed = verdict.is_phish

        outcome = PipelineOutcome(verdict=verdict, user_confirmed=confirmed)

        if not confirmed:
            return outcome

        if inbox:
            outcome.inbox_scan = self.run_inbox_scan(verdict, inbox)

        outcome.ioc_submission = self.submit_iocs(verdict)
        return outcome
