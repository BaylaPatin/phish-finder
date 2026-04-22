"""


Fusion strategy:
    - Weighted score: 0.5 * classifier + 0.3 * url + 0.2 * header
    - Any single strong signal (>= 0.9) can raise the final score on its own.
    - is_phish = final_score >= DECISION_THRESHOLD
"""

from __future__ import annotations

from interface import (
    ClassifierResult,
    HeaderAnalysisResult,
    URLAnalysisResult,
    Verdict,
)

DECISION_THRESHOLD = 0.55

W_CLASSIFIER = 0.5
W_URL = 0.3
W_HEADER = 0.2


def _classifier_phish_score(result: ClassifierResult) -> float:
    if result.label.lower() == "phish":
        return result.confidence
    return 1.0 - result.confidence


def build_verdict(
    classifier_result: ClassifierResult,
    url_result: URLAnalysisResult,
    header_result: HeaderAnalysisResult,
) -> Verdict:
    clf_score = _classifier_phish_score(classifier_result)
    url_score = url_result.aggregate_score
    hdr_score = header_result.score

    weighted = (
        W_CLASSIFIER * clf_score
        + W_URL * url_score
        + W_HEADER * hdr_score
    )
    # If any single signal is overwhelming, don't let the others dilute it.
    final_score = max(weighted, clf_score if clf_score >= 0.9 else 0,
                      url_score if url_score >= 0.9 else 0,
                      hdr_score if hdr_score >= 0.9 else 0)

    is_phish = final_score >= DECISION_THRESHOLD

    explanation = _build_explanation(
        is_phish, final_score, classifier_result, url_result, header_result
    )

    iocs = _extract_iocs(url_result, header_result)

    return Verdict(
        is_phish=is_phish,
        confidence=round(final_score, 3),
        explanation=explanation,
        classifier_result=classifier_result,
        url_result=url_result,
        header_result=header_result,
        iocs=iocs,
    )


def _build_explanation(
    is_phish: bool,
    score: float,
    clf: ClassifierResult,
    url: URLAnalysisResult,
    hdr: HeaderAnalysisResult,
) -> str:
    lines: list[str] = []
    headline = "PHISHING LIKELY" if is_phish else "Looks benign"
    lines.append(f"{headline} (confidence {score:.0%})")

    lines.append(
        f"- Classifier: {clf.label} @ {clf.confidence:.0%} confidence"
    )

    if url.urls_found:
        worst = max(url.signals, key=lambda s: s.score, default=None)
        lines.append(
            f"- URLs: {len(url.urls_found)} found, "
            f"aggregate risk {url.aggregate_score:.0%}"
        )
        if worst and worst.score > 0:
            flags = []
            if worst.virustotal_malicious:
                flags.append(
                    f"VT {worst.virustotal_malicious}/{worst.virustotal_total}"
                )
            if worst.google_safe_browsing_hit:
                flags.append("Google Safe Browsing")
            if worst.phishtank_hit:
                flags.append("PhishTank")
            if flags:
                lines.append(f"  worst: {worst.url} — {', '.join(flags)}")
    else:
        lines.append("- URLs: none found in body")

    auth_parts = []
    for name, passed in (
        ("SPF", hdr.spf_pass),
        ("DKIM", hdr.dkim_pass),
        ("DMARC", hdr.dmarc_pass),
    ):
        if passed is True:
            auth_parts.append(f"{name} pass")
        elif passed is False:
            auth_parts.append(f"{name} FAIL")
        else:
            auth_parts.append(f"{name} n/a")
    lines.append(f"- Headers: {', '.join(auth_parts)}")

    if hdr.from_reply_to_mismatch:
        lines.append("  From / Reply-To mismatch detected")
    if hdr.suspicious_domains:
        lines.append(
            f"  Suspicious domains: {', '.join(hdr.suspicious_domains)}"
        )

    return "\n".join(lines)


def _extract_iocs(
    url_result: URLAnalysisResult,
    header_result: HeaderAnalysisResult,
) -> list[str]:
    iocs: list[str] = []
    iocs.extend(url_result.urls_found)
    iocs.extend(header_result.suspicious_domains)
    # dedupe while preserving order
    seen: set[str] = set()
    deduped: list[str] = []
    for ioc in iocs:
        if ioc not in seen:
            seen.add(ioc)
            deduped.append(ioc)
    return deduped
