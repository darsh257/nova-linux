import re
from collections import Counter


def normalize_log(line):
    """
    Remove timestamps, hostnames, PIDs and other changing fields
    so repeated versions of the same message can be grouped.
    """

    line = line.strip()

    # Remove journal timestamp
    line = re.sub(
        r"^[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d\s+",
        "",
        line
    )

    # Remove hostname
    line = re.sub(
        r"^[\w.-]+\s+",
        "",
        line
    )

    # Normalize PIDs
    line = re.sub(
        r"\[\d+\]",
        "[PID]",
        line
    )

    # Normalize hexadecimal addresses
    line = re.sub(
        r"0x[0-9a-fA-F]+",
        "0xADDR",
        line
    )

    # Normalize repeated whitespace
    line = re.sub(
        r"\s+",
        " ",
        line
    )

    return line.strip()


def classify_log(line):
    """
    Classify a log message into a broad diagnostic category.
    """

    lower = line.lower()

    if "acpi" in lower:
        return "acpi"

    if "chronyd" in lower or "ntp" in lower:
        return "time_sync"

    if "nvidia" in lower or "gpu" in lower:
        return "gpu"

    if "bluetooth" in lower:
        return "bluetooth"

    if "network" in lower or "networkmanager" in lower:
        return "network"

    if "systemd" in lower and "failed" in lower:
        return "service"

    if "failed to start" in lower:
        return "service"

    if "oom" in lower or "out of memory" in lower:
        return "memory"

    if "disk" in lower or "filesystem" in lower:
        return "storage"

    if "kernel" in lower:
        return "kernel"

    return "general"


def classify_severity(line):
    """
    Estimate severity from the log message itself.

    This does NOT confirm that the system is actually unhealthy.
    It only describes the log's apparent severity.
    """

    lower = line.lower()

    if "critical" in lower or "panic" in lower:
        return "critical"

    if "error" in lower or "failed" in lower:
        return "error"

    if "warning" in lower or "warn" in lower:
        return "warning"

    return "info"


def analyze_log_lines(lines):
    """
    Process raw journal lines.

    Returns grouped and summarized log evidence.
    """

    if not lines:
        return {
            "total_lines": 0,
            "unique_messages": 0,
            "groups": []
        }

    normalized = []

    for line in lines:

        if not line.strip():
            continue

        normalized_line = normalize_log(line)

        if normalized_line:
            normalized.append(normalized_line)

    counts = Counter(normalized)

    groups = []

    for message, count in counts.most_common():

        groups.append({
            "message": message,
            "occurrences": count,
            "category": classify_log(message),
            "log_severity": classify_severity(message)
        })

    return {
        "total_lines": len(normalized),
        "unique_messages": len(counts),
        "groups": groups
    }


def build_log_intelligence(log_data):
    """
    Convert NOVA's raw log telemetry into structured intelligence.
    """

    errors = log_data["errors"]["stdout"]
    warnings = log_data["warnings"]["stdout"]

    error_lines = errors.splitlines()
    warning_lines = warnings.splitlines()

    error_analysis = analyze_log_lines(error_lines)
    warning_analysis = analyze_log_lines(warning_lines)

    return {
        "errors": error_analysis,
        "warnings": warning_analysis,

        "policy": {
            "log_messages_are_observations": True,
            "repeated_messages_are_grouped": True,
            "logs_alone_do_not_confirm_system_failure": True
        }
    }