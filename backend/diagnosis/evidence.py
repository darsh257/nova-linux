from backend.diagnosis.log_intelligence import (
    build_log_intelligence
)

from backend.diagnosis.storage_intelligence import (
    analyze_storage
)


def build_evidence(data, findings, correlations):

    # -------------------------------------------------
    # LOG INTELLIGENCE
    # -------------------------------------------------

    log_intelligence = build_log_intelligence(
        data["logs"]
    )

    # -------------------------------------------------
    # STORAGE INTELLIGENCE
    # -------------------------------------------------

    storage_intelligence = analyze_storage(
        data.get("storage", {})
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
    # DETERMINISTIC ANOMALY STATE
    # -------------------------------------------------

    # A confirmed anomaly exists ONLY when the
    # deterministic rules engine or correlation engine
    # has produced evidence.

    confirmed_anomaly = bool(
        findings or correlations
    )

    # -------------------------------------------------
    # EVIDENCE OBJECT
    # -------------------------------------------------

    return {

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
                    cpu["usage_percent"]
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
        # STORAGE INTELLIGENCE
        # =============================================

        "storage_intelligence":
            storage_intelligence,

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
                True
        }
    }