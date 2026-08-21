from backend.diagnosis.process_classifier import classify_process
from backend.diagnosis.service_classifier import (
    classify_service,
    parse_failed_services,
)


# ============================================================
# MEMORY RULES
# ============================================================

def check_memory(data):

    findings = []

    memory = data["memory"]["memory"]
    swap = data["memory"]["swap"]

    memory_usage = memory["usage_percent"]
    swap_usage = swap["usage_percent"]

    # --------------------------------------------------
    # SEVERE MEMORY PRESSURE
    # --------------------------------------------------

    if memory_usage >= 90 and swap_usage >= 50:

        findings.append({
            "id": "memory_pressure",
            "severity": "critical",
            "confidence": 0.95,

            "title": "Severe memory pressure",

            "evidence": [
                f"Memory usage is {memory_usage}%",
                f"Swap usage is {swap_usage}%"
            ],

            "memory": {
                "usage_percent": memory_usage,
                "total_mb": memory["total_mb"],
                "used_mb": memory["used_mb"],
                "available_mb": memory["available_mb"]
            },

            "swap": {
                "usage_percent": swap_usage,
                "total_mb": swap["total_mb"],
                "used_mb": swap["used_mb"]
            }
        })

        return findings

    # --------------------------------------------------
    # HIGH MEMORY USAGE
    #
    # High usage_percent alone is NOT sufficient on a
    # large-RAM machine (e.g. 90% of 32 GB = 3.2 GB free).
    #
    # We require available_mb to be below a meaningful
    # threshold:
    #
    #   < 512 MB  → critical candidate (combined below)
    #   < 1024 MB → warn even at 85% usage
    #   >= 1024 MB → no warning purely from %
    # --------------------------------------------------

    available_mb = memory["available_mb"]

    if memory_usage >= 85 and available_mb < 1024:

        findings.append({
            "id": "high_memory",
            "severity": "warning",
            "confidence": 0.85,

            "title": "High memory usage with low available memory",

            "evidence": [
                f"Memory usage is {memory_usage}%",
                f"Available memory is {available_mb} MB",
                "Available memory is below 1024 MB"
            ],

            "memory": {
                "usage_percent": memory_usage,
                "total_mb": memory["total_mb"],
                "used_mb": memory["used_mb"],
                "available_mb": available_mb
            },

            "swap": {
                "usage_percent": swap_usage,
                "total_mb": swap["total_mb"],
                "used_mb": swap["used_mb"]
            }
        })

    # --------------------------------------------------
    # HIGH SWAP USAGE
    # --------------------------------------------------

    if swap_usage >= 50:

        findings.append({
            "id": "high_swap",
            "severity": "warning",
            "confidence": 0.85,

            "title": "High swap usage",

            "evidence": [
                f"Swap usage is {swap_usage}%",
                f"Swap used is {swap['used_mb']} MB"
            ],

            "memory": {
                "usage_percent": memory_usage,
                "available_mb": memory["available_mb"]
            },

            "swap": {
                "usage_percent": swap_usage,
                "total_mb": swap["total_mb"],
                "used_mb": swap["used_mb"]
            }
        })

    return findings

# ============================================================
# CPU RULES
# ============================================================

def check_cpu(data):
    findings = []

    cpu = data["cpu"]["usage_percent"]

    # Critical system-wide CPU saturation
    if cpu >= 90:

        findings.append({
            "id": "cpu_saturation",
            "severity": "critical",
            "confidence": 0.90,
            "title": "High CPU utilization",
            "evidence": [
                f"CPU usage is {cpu}%"
            ]
        })

    # Elevated system-wide CPU usage
    elif cpu >= 75:

        findings.append({
            "id": "high_cpu",
            "severity": "warning",
            "confidence": 0.80,
            "title": "Elevated CPU utilization",
            "evidence": [
                f"CPU usage is {cpu}%"
            ]
        })

    return findings


# ============================================================
# DISK RULES
# ============================================================

def check_disk(data):

    findings = []

    disk = data["disk"]

    usage = disk["usage_percent"]

    filesystem = disk["filesystem"]
    total_kb = disk["total_kb"]
    used_kb = disk["used_kb"]
    available_kb = disk["available_kb"]

    # --------------------------------------------------
    # CRITICAL DISK USAGE
    # --------------------------------------------------

    if usage >= 95:

        findings.append({
            "id": "disk_critical",
            "severity": "critical",
            "confidence": 0.95,

            "title": "Critical disk usage",

            "evidence": [
                f"Filesystem {filesystem}",
                f"Disk usage is {usage}%",
                f"Available space is {available_kb} KB"
            ],

            "disk": {
                "filesystem": filesystem,
                "total_kb": total_kb,
                "used_kb": used_kb,
                "available_kb": available_kb,
                "usage_percent": usage
            }
        })

        return findings

    # --------------------------------------------------
    # HIGH DISK USAGE
    # --------------------------------------------------

    if usage >= 85:

        findings.append({
            "id": "disk_pressure",
            "severity": "warning",
            "confidence": 0.85,

            "title": "High disk usage",

            "evidence": [
                f"Filesystem {filesystem}",
                f"Disk usage is {usage}%",
                f"Available space is {available_kb} KB"
            ],

            "disk": {
                "filesystem": filesystem,
                "total_kb": total_kb,
                "used_kb": used_kb,
                "available_kb": available_kb,
                "usage_percent": usage
            }
        })

    return findings

# ============================================================
# PROCESS RULES
# ============================================================

def check_processes(data):
    findings = []

    processes = data["processes"]["top_cpu"]

    cpu_count = data["cpu"]["cpu_count"]
    system_cpu = data["cpu"]["usage_percent"]

    for process in processes:

        cpu = process["cpu_percent"]
        memory = process["memory_percent"]
        elapsed = process.get("elapsed", "00:00")
        state = process.get("state", "")
        command = process["command"]

        # ----------------------------------------------------
        # Calculate process runtime
        # ----------------------------------------------------

        try:

            elapsed_parts = elapsed.split(":")

            if len(elapsed_parts) == 2:

                minutes = int(elapsed_parts[0])
                seconds = int(elapsed_parts[1])

                runtime_seconds = (
                    minutes * 60
                    + seconds
                )

            elif len(elapsed_parts) == 3:

                hours = int(elapsed_parts[0])
                minutes = int(elapsed_parts[1])
                seconds = int(elapsed_parts[2])

                runtime_seconds = (
                    hours * 3600
                    + minutes * 60
                    + seconds
                )

            else:

                runtime_seconds = 0

        except (ValueError, TypeError):

            runtime_seconds = 0

        # ----------------------------------------------------
        # Ignore short-lived processes
        #
        # This prevents NOVA's own python3 command,
        # ps, etc. from being detected as anomalies.
        # ----------------------------------------------------

        if runtime_seconds < 10:
            continue

        # ----------------------------------------------------
        # High CPU process threshold
        # ----------------------------------------------------

        if cpu < 80:
            continue

        # ----------------------------------------------------
        # Classify the process
        # ----------------------------------------------------

        classification = classify_process(command)

        # ----------------------------------------------------
        # Convert process CPU percentage into
        # approximate CPU cores being consumed.
        #
        # Example:
        #
        # 100% = 1 CPU core
        # 150% = 1.5 CPU cores
        # 200% = 2 CPU cores
        # ----------------------------------------------------

        cpu_cores_used = cpu / 100

        # ----------------------------------------------------
        # Determine system-wide CPU pressure
        # ----------------------------------------------------

        system_pressure = system_cpu >= 75

        # ----------------------------------------------------
        # Determine severity
        #
        # A high-CPU process alone is a warning.
        #
        # If the entire system is also under CPU pressure
        # and the process consumes >= 2 cores,
        # escalate to critical.
        # ----------------------------------------------------

        severity = "warning"

        if system_pressure and cpu_cores_used >= 2:

            severity = "critical"

        # ----------------------------------------------------
        # Determine confidence
        #
        # Longer-running processes provide stronger evidence.
        # ----------------------------------------------------

        confidence = 0.85

        if runtime_seconds >= 60:

            confidence = 0.90

        if runtime_seconds >= 300:

            confidence = 0.95

        # ----------------------------------------------------
        # Build evidence
        # ----------------------------------------------------

        evidence = [

            f"PID {process['pid']}",

            f"CPU usage {cpu}%",

            (
                f"Approximately "
                f"{cpu_cores_used:.2f} CPU cores used"
            ),

            f"Process memory usage {memory}%",

            f"Process runtime {elapsed}",

            f"Process state {state}",

            (
                f"Process classification "
                f"{classification}"
            ),

            (
                f"System CPU usage "
                f"{system_cpu}% across "
                f"{cpu_count} CPUs"
            )
        ]

        # ----------------------------------------------------
        # Create deterministic finding
        # ----------------------------------------------------

        findings.append({

            "id": "high_cpu_process",

            "severity": severity,

            "confidence": confidence,

            "title": (
                f"High CPU process: "
                f"{command}"
            ),

            "evidence": evidence,

            "process": {

                "pid": process["pid"],

                "command": command,

                "cpu_percent": cpu,

                "memory_percent": memory,

                "cpu_cores_used": round(
                    cpu_cores_used,
                    2
                ),

                "elapsed": elapsed,

                "state": state
            },

            # Deterministic process classification
            "classification": classification,

            "system_context": {

                "cpu_count": cpu_count,

                "cpu_usage_percent": system_cpu,

                "system_cpu_pressure": system_pressure
            }
        })

    return findings


# ============================================================
# SYSTEMD SERVICE RULES
# ============================================================

# Confidence mapping by tier.
# Known tiers have high confidence; unknown is slightly lower.
_SERVICE_TIER_CONFIDENCE = {
    "critical_system": 0.97,
    "optional_system": 0.90,
    "user_application": 0.88,
    "development": 0.80,
    "unknown": 0.75,
}


def check_services(data):
    """
    Inspect failed systemd services and produce a per-service finding
    with severity proportional to the service tier.

    Severity mapping
    ----------------
    critical_system  → critical
    optional_system  → warning
    user_application → warning
    development      → info
    unknown          → warning
    """

    findings = []

    failed_output = (
        data["services"]["failed_services"]["stdout"]
    )

    if not failed_output.strip():
        return findings

    service_names = parse_failed_services(failed_output)

    for service_name in service_names:

        classification = classify_service(service_name)

        tier = classification["tier"]
        severity = classification["severity"]
        explanation = classification["explanation"]
        confidence = _SERVICE_TIER_CONFIDENCE.get(tier, 0.75)

        findings.append({

            "id": "failed_service",

            "severity": severity,

            "confidence": confidence,

            "title": (
                f"Failed service: {service_name}"
            ),

            "evidence": [
                f"Service {service_name!r} is in a failed state",
                f"Service tier: {tier}",
                explanation,
            ],

            "service_name": service_name,

            "service_tier": tier,

            "classification": classification,
        })

    return findings


# ============================================================
# MAIN RULE ENGINE
# ============================================================

def run_rules(data):

    findings = []

    findings.extend(
        check_memory(data)
    )

    findings.extend(
        check_cpu(data)
    )

    findings.extend(
        check_disk(data)
    )

    findings.extend(
        check_processes(data)
    )

    findings.extend(
        check_services(data)
    )

    return findings