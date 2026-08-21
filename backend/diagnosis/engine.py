from backend.diagnosis.rules import run_rules
from backend.diagnosis.correlation import correlate
from backend.diagnosis.evidence import build_evidence
from backend.diagnosis.storage_intelligence import analyze_storage
from backend.diagnosis.network_connectivity import analyze_connectivity


def analyze(data):

    # ============================================================
    # 1. DETERMINISTIC RULES
    # ============================================================

    findings = run_rules(data)

    # ============================================================
    # 2. STORAGE INTELLIGENCE
    # ============================================================

    storage_intelligence = analyze_storage(
        data["storage"]
    )

    # ============================================================
    # 3. NETWORK CONNECTIVITY INTELLIGENCE
    # ============================================================

    network_connectivity = analyze_connectivity(
        data["network"]
    )

    # ============================================================
    # 4. ADD INTELLIGENCE RESULTS TO DATA CONTEXT
    #
    # Correlation engine can now use:
    # - deterministic findings
    # - storage intelligence
    # - network connectivity
    # ============================================================

    correlation_data = dict(data)

    correlation_data["storage_intelligence"] = (
        storage_intelligence
    )

    correlation_data["network_connectivity"] = (
        network_connectivity
    )

    # ============================================================
    # 5. CORRELATION ENGINE
    # ============================================================

    correlations = correlate(
        correlation_data,
        findings
    )

    # ============================================================
    # 6. BUILD CORE EVIDENCE
    # ============================================================

    evidence = build_evidence(
        data,
        findings,
        correlations,
        storage_intelligence
    )

    # ============================================================
    # 7. ATTACH INTELLIGENCE RESULTS
    # ============================================================

    evidence["storage_intelligence"] = (
        storage_intelligence
    )

    evidence["network_connectivity"] = (
        network_connectivity
    )

    # ============================================================
    # 8. COMBINE ALL CONFIRMED FINDINGS
    # ============================================================

    all_findings = findings + correlations

    # ============================================================
    # 9. DETERMINE ANOMALY-LEVEL ITEMS
    #
    # Only "warning" or "critical" items (not tagged as
    # type="observation") are genuine anomalies.
    # This mirrors the _is_anomaly() check in evidence.py.
    # ============================================================

    def _is_anomaly(item):
        severity = item.get("severity", "info")
        item_type = item.get("type", "anomaly")

        if item_type == "observation":
            return False

        return severity in ("warning", "critical")

    anomaly_items = [
        item for item in all_findings
        if _is_anomaly(item)
    ]

    # ============================================================
    # 10. HEALTHY SYSTEM
    # (no anomaly-level items at all)
    # ============================================================

    if not anomaly_items:

        evidence["diagnostic_state"] = {
            "confirmed_anomaly": False,
            "finding_count": len(findings),
            "correlation_count": len(correlations),
            "observation_count": len(all_findings) - len(anomaly_items),
            "status": "healthy",
            "severity": "none"
        }

        return evidence

    # ============================================================
    # 11. SEVERITY ORDER
    # ============================================================

    severity_order = {
        "critical": 3,
        "warning": 2,
        "info": 1,
        "none": 0
    }

    # ============================================================
    # 12. FIND HIGHEST SEVERITY AMONG ANOMALY ITEMS
    # ============================================================

    highest = max(
        anomaly_items,
        key=lambda x: severity_order.get(
            x.get("severity", "info"),
            1
        )
    )

    highest_severity = highest.get(
        "severity",
        "info"
    )

    # ============================================================
    # 13. UPDATE DIAGNOSTIC STATE
    # ============================================================

    evidence["diagnostic_state"] = {
        "confirmed_anomaly": True,
        "finding_count": len(findings),
        "correlation_count": len(correlations),
        "observation_count": len(all_findings) - len(anomaly_items),
        "status": "anomaly_detected",
        "severity": highest_severity
    }

    return evidence


if __name__ == "__main__":

    import json

    from backend.core import collect_system_info

    print(
        "Collecting Linux telemetry..."
    )

    data = collect_system_info()

    print(
        "Running deterministic evidence engine..."
    )

    result = analyze(data)

    print(
        json.dumps(
            result,
            indent=2
        )
    )