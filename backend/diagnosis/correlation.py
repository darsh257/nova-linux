from backend.diagnosis.service_classifier import parse_failed_services
from backend.diagnosis.process_classifier import classify_process


def correlate(data, findings):

    correlations = []

    cpu = data["cpu"]
    cpu_usage = cpu["usage_percent"]
    cpu_count = cpu["cpu_count"]

    # Load average relative to core count is a richer saturation signal.
    # load1 may be None if /proc/loadavg could not be read.
    load1 = cpu.get("load1")

    top_cpu = data["processes"]["top_cpu"]

    # ============================================================
    # CPU + PROCESS CORRELATION
    #
    # Only fire when the SYSTEM is actually under CPU pressure
    # (system-wide usage_percent >= 80).
    #
    # load1 > cpu_count adds additional evidence of saturation.
    # Process CPU% alone (which can exceed 100% on multi-core)
    # does NOT count as system saturation.
    # ============================================================

    if cpu_usage >= 80:

        # Optionally strengthen evidence with load average
        load_saturated = (
            load1 is not None
            and load1 > cpu_count
        )

        heavy_processes = []

        for process in top_cpu[:5]:

            if process["cpu_percent"] >= 20:

                heavy_processes.append({
                    "pid": process["pid"],
                    "command": process["command"],
                    "cpu_percent": process["cpu_percent"],
                    "cpu_cores_used": round(
                        process["cpu_percent"] / 100,
                        2
                    )
                })

        if heavy_processes:

            reason = [
                f"Overall CPU usage is {cpu_usage}%",
                f"System has {cpu_count} CPUs",
                "One or more processes are consuming significant CPU",
            ]

            if load_saturated:
                reason.append(
                    f"Load average ({load1:.2f}) exceeds CPU count ({cpu_count})"
                )

            correlations.append({
                "id": "cpu_process_correlation",

                "severity": (
                    "critical"
                    if cpu_usage >= 95
                    else "warning"
                ),

                "confidence": 0.94 if load_saturated else 0.92,

                "title": "CPU saturation linked to processes",

                "reason": reason,

                "related_processes": heavy_processes
            })

    # ============================================================
    # MEMORY + SWAP + PROCESS CORRELATION
    # ============================================================

    memory = data["memory"]["memory"]
    swap = data["memory"]["swap"]

    memory_usage = memory["usage_percent"]
    swap_usage = swap["usage_percent"]
    available_mb = memory["available_mb"]

    # Severe pressure: very low available memory AND high swap
    if memory_usage >= 90 and swap_usage >= 50 and available_mb < 512:

        top_memory = data["processes"]["top_memory"]

        correlations.append({

            "id": "memory_pressure_correlation",

            "severity": "critical",

            "confidence": 0.97,

            "title": "Severe memory pressure detected",

            "reason": [
                f"Memory usage is {memory_usage}%",
                f"Available memory is {available_mb} MB (below 512 MB)",
                f"Swap usage is {swap_usage}%"
            ],

            "related_processes": [

                {
                    "pid": p["pid"],
                    "command": p["command"],
                    "memory_percent": p["memory_percent"]
                }

                for p in top_memory[:5]
            ]
        })

    # Memory + high memory process
    if memory_usage >= 85 and available_mb < 1024:

        memory_processes = []

        for process in data["processes"]["top_memory"][:5]:

            if process["memory_percent"] >= 10:

                memory_processes.append({

                    "pid": process["pid"],

                    "command": process["command"],

                    "memory_percent": process["memory_percent"]
                })

        if memory_processes:

            correlations.append({

                "id": "memory_process_correlation",

                "severity": (
                    "critical"
                    if memory_usage >= 95 and available_mb < 512
                    else "warning"
                ),

                "confidence": 0.90,

                "title": "High memory usage linked to processes",

                "reason": [
                    f"System memory usage is {memory_usage}%",
                    f"Available memory is {available_mb} MB",
                    "One or more processes account for significant memory usage"
                ],

                "related_processes": memory_processes
            })

    # ============================================================
    # SERVICE + LOG CORRELATION
    #
    # Previously: ANY failed service + ANY log error = correlation.
    # Now: we require a log message that specifically references
    #      the name of the failed service.
    #
    # This prevents ACPI/Bluetooth log noise from being correlated
    # with an unrelated service failure (e.g. ollama.service).
    # ============================================================

    failed_services_output = (
        data["services"]["failed_services"]["stdout"]
    )

    log_errors = (
        data["logs"]["errors"]["stdout"]
    )

    if failed_services_output.strip() and log_errors.strip():

        # Extract the individual service names
        failed_names = parse_failed_services(
            failed_services_output
        )

        # Build bare names for matching (strip ".service" suffix)
        bare_names = set()

        for unit in failed_names:
            bare_names.add(unit.lower())
            if unit.lower().endswith(".service"):
                bare_names.add(unit.lower()[: -len(".service")])

        # Match log lines that reference a failed service by name
        matched_logs = []

        for line in log_errors.splitlines():

            lower_line = line.lower()

            for bare in bare_names:

                if bare and bare in lower_line:

                    matched_logs.append(line.strip())
                    break   # one service match per line is enough

        if matched_logs:

            correlations.append({

                "id": "service_log_correlation",

                "severity": "warning",

                # Confidence scales with number of matching log lines;
                # cap at 0.96
                "confidence": min(
                    0.75 + 0.05 * len(matched_logs),
                    0.96
                ),

                "title": "Failed service referenced in error logs",

                "reason": [
                    "One or more services are in a failed state",
                    "Journal error log contains messages naming the failed service(s)",
                ],

                "failed_services": failed_names,

                "matching_log_lines": matched_logs[:10],
            })

    # ============================================================
    # NETWORK CONNECTIVITY CORRELATION
    # ============================================================

    network = data.get("network")

    if network:

        interfaces = network.get(
            "interfaces",
            {}
        )

        routes = network.get(
            "routes",
            {}
        )

        # --------------------------------------------------------
        # Extract interface output
        # --------------------------------------------------------

        interface_output = interfaces.get(
            "stdout",
            ""
        )

        route_output = routes.get(
            "stdout",
            ""
        )

        # --------------------------------------------------------
        # Detect absence of an active interface
        # --------------------------------------------------------

        interface_lines = (
            interface_output.splitlines()
            if interface_output
            else []
        )

        active_interfaces = []

        for line in interface_lines:

            parts = line.split()

            if len(parts) >= 2:

                name = parts[0]
                state = parts[1]

                if state == "UP" and name != "lo":

                    active_interfaces.append(name)

        # --------------------------------------------------------
        # No active network interface
        # --------------------------------------------------------

        if not active_interfaces:

            correlations.append({

                "id": "network_no_active_interface",

                "severity": "critical",

                "confidence": 0.96,

                "title": "No active network interface detected",

                "reason": [
                    "No non-loopback network interface is UP",
                    "External network connectivity is therefore unlikely"
                ]
            })

        # --------------------------------------------------------
        # Active interface but no default route
        # --------------------------------------------------------

        if active_interfaces and "default" not in route_output:

            correlations.append({

                "id": "network_missing_default_route",

                "severity": "warning",

                "confidence": 0.93,

                "title": "Active network interface has no default route",

                "reason": [
                    f"Active interface: {active_interfaces[0]}",
                    "No default route was detected"
                ]
            })

    # ============================================================
    # NETWORK CONNECTIVITY INTELLIGENCE
    # ============================================================

    connectivity = data.get(
        "network_connectivity"
    )

    if connectivity:

        connectivity_state = connectivity.get(
            "connectivity_state",
            {}
        )

        gateway = connectivity_state.get(
            "gateway",
            {}
        )

        dns = connectivity_state.get(
            "dns",
            {}
        )

        external = connectivity_state.get(
            "external_connectivity",
            {}
        )

        # --------------------------------------------------------
        # Gateway failure
        # --------------------------------------------------------

        if (
            gateway.get("tested")
            and not gateway.get("reachable")
        ):

            correlations.append({

                "id": "gateway_unreachable",

                "severity": "critical",

                "confidence": 0.97,

                "title": "Default network gateway is unreachable",

                "reason": [
                    f"Gateway: {gateway.get('gateway')}",
                    "Gateway connectivity test failed"
                ]
            })

        # --------------------------------------------------------
        # DNS failure with reachable gateway
        # --------------------------------------------------------

        if (
            gateway.get("reachable")
            and dns.get("tested")
            and not dns.get("resolved")
        ):

            correlations.append({

                "id": "dns_failure",

                "severity": "warning",

                "confidence": 0.95,

                "title": "DNS resolution failure",

                "reason": [
                    "Network gateway is reachable",
                    "DNS resolution failed"
                ]
            })

        # --------------------------------------------------------
        # External connectivity failure
        # --------------------------------------------------------

        if (
            dns.get("resolved")
            and external.get("tested")
            and not external.get("reachable")
        ):

            correlations.append({

                "id": "external_connectivity_failure",

                "severity": "warning",

                "confidence": 0.94,

                "title": "External network connectivity failure",

                "reason": [
                    "DNS resolution is working",
                    "External HTTPS connectivity failed"
                ]
            })

    # ============================================================
    # STORAGE + DISK PRESSURE CORRELATION
    # ============================================================

    storage = data.get(
        "storage"
    )

    disk = data.get(
        "disk"
    )

    if storage and disk:

        disk_usage = disk.get(
            "usage_percent",
            0
        )

        large_files = storage.get(
            "large_files",
            []
        )

        # --------------------------------------------------------
        # Disk pressure + large files
        # --------------------------------------------------------

        if disk_usage >= 85 and large_files:

            correlations.append({

                "id": "disk_storage_correlation",

                "severity": (
                    "critical"
                    if disk_usage >= 95
                    else "warning"
                ),

                "confidence": 0.91,

                "title": "High disk usage supported by large files",

                "reason": [
                    f"Disk usage is {disk_usage}%",
                    f"{len(large_files)} large files were identified"
                ],

                "large_files": [

                    {
                        "path": item.get("path"),
                        "size_human": item.get(
                            "size_human"
                        ),
                        "classification": item.get(
                            "classification"
                        )
                    }

                    for item in large_files[:10]
                ]
            })

    # ============================================================
    # AI WORKLOAD OBSERVATION
    #
    # Phase 7 requirement:
    #
    # When an AI workload process is active, produce an informational
    # observation regardless of system CPU level.
    #
    # This observation:
    #   - uses severity "info"
    #   - is tagged type "observation" (NOT an anomaly)
    #   - must NOT cause confirmed_anomaly = True
    #   - must NOT cause status = anomaly_detected
    #
    # The engine.py filters "info" observations out of the anomaly
    # severity calculation (see diagnostic_state logic).
    # ============================================================

    ai_processes = []

    for process in top_cpu[:10]:

        command = process.get("command", "")

        category = classify_process(command)

        if category == "ai_workload":

            cpu_pct = process["cpu_percent"]
            cpu_cores = round(cpu_pct / 100, 2)

            ai_processes.append({
                "pid": process["pid"],
                "command": command,
                "cpu_percent": cpu_pct,
                "cpu_cores_used": cpu_cores,
                "classification": category,
            })

    if ai_processes:

        reason_lines = [
            f"System CPU: {cpu_usage}% across {cpu_count} cores",
        ]

        for ap in ai_processes:
            reason_lines.append(
                f"{ap['command']} (PID {ap['pid']}) is using "
                f"{ap['cpu_percent']}% CPU "
                f"≈ {ap['cpu_cores_used']} CPU core(s)"
            )

        correlations.append({

            "id": "ai_workload_observation",

            # info severity — deliberately not warning or critical
            "severity": "info",

            # Observations use a type tag so the engine can
            # distinguish them from genuine anomaly correlations.
            "type": "observation",

            "confidence": 0.90,

            "title": "AI workload active",

            "reason": reason_lines,

            "related_processes": ai_processes,

            "system_context": {
                "cpu_count": cpu_count,
                "system_cpu_usage_percent": cpu_usage,
                "load1": load1,
            }
        })

    # ============================================================
    # RETURN CORRELATIONS
    # ============================================================

    return correlations