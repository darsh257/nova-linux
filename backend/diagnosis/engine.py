from diagnosis.rules import run_rules
from diagnosis.correlation import correlate


def analyze(data):

    findings = run_rules(data)

    correlations = correlate(
        data,
        findings
    )

    all_findings = findings + correlations

    if not all_findings:

        return {
            "status": "healthy",
            "severity": "info",
            "summary": "No major anomalies detected.",
            "findings": [],
            "correlations": []
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
        "correlations": correlations
    }
