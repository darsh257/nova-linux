def check_memory(data):
    findings = []

    memory = data["memory"]["memory"]
    swap = data["memory"]["swap"]

    usage = memory["usage_percent"]
    swap_usage = swap["usage_percent"]

    if usage >= 90 and swap_usage >= 50:
        findings.append({
            "id": "memory_pressure",
            "severity": "critical",
            "confidence": 0.95,
            "title": "Severe memory pressure",
            "evidence": [
                f"Memory usage is {usage}%",
                f"Swap usage is {swap_usage}%"
            ]
        })

    elif usage >= 85:
        findings.append({
            "id": "high_memory",
            "severity": "warning",
            "confidence": 0.85,
            "title": "High memory usage",
            "evidence": [
                f"Memory usage is {usage}%"
            ]
        })

    return findings


def check_cpu(data):
    findings = []

    cpu = data["cpu"]["usage_percent"]

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


def check_disk(data):
    findings = []

    usage = data["disk"]["usage_percent"]

    if usage >= 95:
        findings.append({
            "id": "disk_critical",
            "severity": "critical",
            "confidence": 0.95,
            "title": "Critical disk usage",
            "evidence": [
                f"Disk usage is {usage}%"
            ]
        })

    elif usage >= 85:
        findings.append({
            "id": "disk_pressure",
            "severity": "warning",
            "confidence": 0.85,
            "title": "High disk usage",
            "evidence": [
                f"Disk usage is {usage}%"
            ]
        })

    return findings


def check_processes(data):
    findings = []

    processes = data["processes"]["top_cpu"]

    for process in processes:

        cpu = process["cpu_percent"]

        if cpu >= 80:

            findings.append({
                "id": "high_cpu_process",
                "severity": "warning",
                "confidence": 0.85,
                "title": f"High CPU process: {process['command']}",
                "evidence": [
                    f"PID {process['pid']}",
                    f"CPU usage {cpu}%"
                ]
            })

    return findings


def check_services(data):
    findings = []

    failed = data["services"]["failed_services"]["stdout"]

    if failed.strip():

        findings.append({
            "id": "failed_services",
            "severity": "critical",
            "confidence": 0.95,
            "title": "One or more systemd services have failed",
            "evidence": failed.splitlines()
        })

    return findings


def run_rules(data):

    findings = []

    findings.extend(check_memory(data))
    findings.extend(check_cpu(data))
    findings.extend(check_disk(data))
    findings.extend(check_processes(data))
    findings.extend(check_services(data))

    return findings
