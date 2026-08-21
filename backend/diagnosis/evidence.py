from backend.diagnosis.log_intelligence import (
    build_log_intelligence
)


def build_evidence(data, findings, correlations, root_cause_candidates, storage_intelligence=None):
    """
    Build the structured evidence dictionary.

    Parameters
    ----------
    data : dict
        Raw telemetry from collect_system_info().
    findings : list
        Deterministic findings from run_rules().
    correlations : list
        Correlations from correlate().
    root_cause_candidates : list
        Root cause candidates from generate_root_cause_candidates().
    storage_intelligence : dict, optional
        Already-computed storage intelligence from analyze_storage().
        If None (e.g. called from tests), no storage section is included.
        Passing this avoids calling analyze_storage() a second time.
    """

    # -------------------------------------------------
    # LOG INTELLIGENCE
    # -------------------------------------------------

    log_intelligence = build_log_intelligence(
        data["logs"]
    )

    # -------------------------------------------------
    # SYSTEM DATA
    # -------------------------------------------------

    memory = data["memory"]["memory"]
    swap = data["memory"]["swap"]
    cpu = data["cpu"]
    disk = data["disk"]

    top_cpu = data["processes"]["top_cpu"]
    top_memory = data["processes"]["top_memory"]

    # -------------------------------------------------
    # CONFIRMED ANOMALY STATE
    #
    # Phase 9 requirement:
    #
    # Informational observations (severity="info" /
    # type="observation") must NOT mark the system as
    # having a confirmed anomaly.
    #
    # Only findings or correlations whose severity is
    # "warning" or "critical" count as real anomalies.
    # -------------------------------------------------

    def _is_anomaly(item):
        """
        Return True when the item is an actual anomaly
        (severity warning or critical), not just an
        informational observation.
        """
        severity = item.get("severity", "info")
        item_type = item.get("type", "anomaly")

        # Explicitly tagged observations are never anomalies
        if item_type == "observation":
            return False

        return severity in ("warning", "critical")

    confirmed_anomaly = any(
        _is_anomaly(f) for f in findings
    ) or any(
        _is_anomaly(c) for c in correlations
    )

    # -------------------------------------------------
    # EVIDENCE OBJECT
    # -------------------------------------------------

    evidence = {

        # =============================================
        # DIAGNOSTIC STATE
        # =============================================

        "diagnostic_state": {

            "confirmed_anomaly":
                confirmed_anomaly,

            "finding_count":
                len(findings),

            "correlation_count":
                len(correlations),

            "status": (
                "anomaly_detected"
                if confirmed_anomaly
                else "healthy"
            )
        },

        # =============================================
        # SYSTEM STATE
        # =============================================

        "system_state": {

            "cpu": {
                "cpu_count":
                    cpu["cpu_count"],

                "usage_percent":
                    cpu["usage_percent"],

                "load1":
                    cpu.get("load1"),

                "load5":
                    cpu.get("load5"),

                "load15":
                    cpu.get("load15"),
            },

            "memory": {

                "total_mb":
                    memory["total_mb"],

                "used_mb":
                    memory["used_mb"],

                "available_mb":
                    memory["available_mb"],

                "usage_percent":
                    memory["usage_percent"]
            },

            "swap": {

                "total_mb":
                    swap["total_mb"],

                "used_mb":
                    swap["used_mb"],

                "usage_percent":
                    swap["usage_percent"]
            },

            "disk": {

                "filesystem":
                    disk["filesystem"],

                "usage_percent":
                    disk["usage_percent"],

                "available_kb":
                    disk["available_kb"]
            }
        },

        # =============================================
        # TOP CPU PROCESSES
        # =============================================

        "top_cpu_processes": [

            {
                "pid":
                    p["pid"],

                "command":
                    p["command"],

                "cpu_percent":
                    p["cpu_percent"],

                "memory_percent":
                    p["memory_percent"]
            }

            for p in top_cpu[:5]
        ],

        # =============================================
        # TOP MEMORY PROCESSES
        # =============================================

        "top_memory_processes": [

            {
                "pid":
                    p["pid"],

                "command":
                    p["command"],

                "cpu_percent":
                    p["cpu_percent"],

                "memory_percent":
                    p["memory_percent"]
            }

            for p in top_memory[:5]
        ],

        # =============================================
        # AUTHORITATIVE FINDINGS
        # =============================================

        "findings":
            findings,

        # =============================================
        # CORRELATED EVIDENCE
        # =============================================

        "correlations":
            correlations,

        # =============================================
        # ROOT CAUSE CANDIDATES
        # =============================================

        "root_cause_candidates":
            root_cause_candidates,

        # =============================================
        # SERVICES
        # =============================================

        "services": {

            "failed":
                data["services"][
                    "failed_services"
                ]["stdout"],

            "running":
                data["services"][
                    "running_services"
                ]["stdout"]
        },

        # =============================================
        # LOG INTELLIGENCE
        # =============================================

        "logs":
            log_intelligence,

        # =============================================
        # DIAGNOSTIC POLICY
        # =============================================

        "diagnostic_policy": {

            # Logs are observations, not proof.
            "log_messages_alone_are_not_proof_of_system_failure":
                True,

            # Root cause requires evidence.
            "root_cause_requires_supporting_evidence":
                True,

            # Correlations strengthen findings.
            "prefer_correlated_evidence":
                True,

            # Deterministic findings always win
            # over AI interpretation.
            "deterministic_findings_have_priority_over_logs":
                True,

            # Isolated messages must remain observations.
            "isolated_log_messages_are_observations":
                True,

            # Storage intelligence is read-only.
            "storage_analysis_is_read_only":
                True,

            # Large files are not automatically anomalies.
            "large_files_are_not_automatically_anomalies":
                True,

            # Cleanup must never happen automatically.
            "automatic_storage_cleanup_disabled":
                True,

            # Info-level observations do not count as anomalies.
            "info_observations_do_not_trigger_anomaly_state":
                True,
        }
    }

    # =============================================
    # STORAGE INTELLIGENCE
    # (already computed by engine.py — no second call)
    # =============================================

    if storage_intelligence is not None:
        evidence["storage_intelligence"] = storage_intelligence

    return evidence