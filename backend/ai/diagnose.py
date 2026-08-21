import json

from backend.ai.ollama_client import ask_qwen
from backend.ai.prompts import build_diagnostic_prompt


def build_ai_evidence(evidence):

    diagnostic_state = evidence.get(
        "diagnostic_state",
        {}
    )

    system_state = evidence.get(
        "system_state",
        {}
    )

    findings = evidence.get(
        "findings",
        []
    )

    correlations = evidence.get(
        "correlations",
        []
    )

    logs = evidence.get(
        "logs",
        {}
    )

    # ---------------------------------------------------------
    # IMPORTANT:
    # Only send a SMALL, summarized representation of logs.
    #
    # Findings are authoritative.
    # Logs are observations only.
    # ---------------------------------------------------------

    log_observations = {}

    error_logs = logs.get("errors", {})
    warning_logs = logs.get("warnings", {})

    if error_logs:
        log_observations["errors"] = {
            "total_lines": error_logs.get("total_lines", 0),
            "unique_messages": error_logs.get("unique_messages", 0),
            "categories": [
                group.get("category")
                for group in error_logs.get("groups", [])
                if group.get("category")
            ]
        }

    if warning_logs:
        log_observations["warnings"] = {
            "total_lines": warning_logs.get("total_lines", 0),
            "unique_messages": warning_logs.get("unique_messages", 0),
            "categories": [
                group.get("category")
                for group in warning_logs.get("groups", [])
                if group.get("category")
            ]
        }

    return {
        # =====================================================
        # AUTHORITATIVE
        # =====================================================

        "diagnostic_state": diagnostic_state,

        "confirmed_findings": findings,

        "correlations": correlations,

        # =====================================================
        # SYSTEM CONTEXT
        # =====================================================

        "system_state": system_state,

        # =====================================================
        # LOG OBSERVATIONS
        # =====================================================

        "log_observations": log_observations,

        # =====================================================
        # AI POLICY
        # =====================================================

        "diagnostic_policy": {
            "findings_are_authoritative": True,
            "correlations_are_supporting_evidence": True,
            "logs_are_observations_only": True,
            "logs_cannot_create_findings": True,
            "logs_cannot_change_severity": True,
            "logs_cannot_create_root_causes": True
        }
    }


def diagnose_with_ai(evidence):

    diagnostic_state = evidence.get(
        "diagnostic_state",
        {}
    )

    confirmed_anomaly = diagnostic_state.get(
        "confirmed_anomaly",
        False
    )

    # ---------------------------------------------------------
    # HEALTHY PATH
    # ---------------------------------------------------------

    if not confirmed_anomaly:

        return (
            "SYSTEM STATUS:\n"
            "HEALTHY\n\n"

            "SUMMARY:\n"
            "No confirmed system anomaly was detected by "
            "NOVA's deterministic evidence engine.\n\n"

            "CONFIRMED ANOMALIES:\n"
            "- None\n\n"

            "CORRELATED EVIDENCE:\n"
            "- None\n\n"

            "LOG OBSERVATIONS:\n"
            "- Log messages may contain warnings or errors, "
            "but they are not confirmed anomalies.\n\n"

            "SYSTEM STATE:\n"
            "- No confirmed resource or process anomaly\n\n"

            "LIKELY ROOT CAUSE:\n"
            "Insufficient evidence to determine the root cause.\n\n"

            "CONFIDENCE:\n"
            "100%\n\n"

            "RECOMMENDED ACTIONS:\n"
            "1. Continue monitoring the system.\n"
            "2. Investigate logs only if they correlate with "
            "a measurable system problem.\n\n"

            "WHY:\n"
            "The deterministic evidence engine found no "
            "confirmed anomaly."
        )

    # ---------------------------------------------------------
    # ANOMALY PATH
    # ---------------------------------------------------------

    ai_evidence = build_ai_evidence(evidence)

    prompt = build_diagnostic_prompt(
        json.dumps(
            ai_evidence,
            indent=2
        )
    )

    result = ask_qwen(prompt)

    return result