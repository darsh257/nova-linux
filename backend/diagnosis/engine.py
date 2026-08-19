from backend.diagnosis.rules import run_rules
from backend.diagnosis.correlation import correlate
from backend.diagnosis.evidence import build_evidence


def analyze(data):

    findings = run_rules(data)

    correlations = correlate(
        data,
        findings
    )

    evidence = build_evidence(
        data,
        findings,
        correlations
    )

    all_findings = findings + correlations

    if not all_findings:

        return {
            "status": "healthy",
            "severity": "info",
            "summary": "No major anomalies detected.",
            "findings": [],
            "correlations": [],
            "evidence": evidence
        }

    severity_order = {
        "critical": 3,
        "warning": 2,
        "info": 1
    }

    highest = max(
        all_findings,
        key=lambda x: severity_order[x["severity"]]
    )

    return {
        "status": "anomaly_detected",
        "severity": highest["severity"],
        "summary": (
            f"{len(all_findings)} "
            "finding(s) detected."
        ),
        "findings": findings,
        "correlations": correlations,
        "evidence": evidence
    }
