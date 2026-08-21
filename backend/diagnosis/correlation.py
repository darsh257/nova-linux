def correlate(data, findings):

    correlations = []

    # ============================================================
    # CPU + PROCESS CORRELATION
    # ============================================================

    cpu_usage = data["cpu"]["usage_percent"]
    cpu_count = data["cpu"]["cpu_count"]

    top_cpu = data["processes"]["top_cpu"]

    if cpu_usage >= 80:

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

            correlations.append({
                "id": "cpu_process_correlation",

                "severity": (
                    "critical"
                    if cpu_usage >= 95
                    else "warning"
                ),

                "confidence": 0.92,

                "title": "CPU saturation linked to processes",

                "reason": [
                    f"Overall CPU usage is {cpu_usage}%",
                    f"System has {cpu_count} CPUs",
                    "One or more processes are consuming significant CPU"
                ],

                "related_processes": heavy_processes
            })

    # ============================================================
    # MEMORY + SWAP + PROCESS CORRELATION
    # ============================================================

    memory = data["memory"]["memory"]
    swap = data["memory"]["swap"]

    memory_usage = memory["usage_percent"]
    swap_usage = swap["usage_percent"]

    if memory_usage >= 90 and swap_usage >= 50:

        top_memory = data["processes"]["top_memory"]

        correlations.append({

            "id": "memory_pressure_correlation",

            "severity": "critical",

            "confidence": 0.97,

            "title": "Severe memory pressure detected",

            "reason": [
                f"Memory usage is {memory_usage}%",
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

    # ============================================================
    # MEMORY + HIGH MEMORY PROCESS
    # ============================================================

    if memory_usage >= 85:

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
                    if memory_usage >= 95
                    else "warning"
                ),

                "confidence": 0.90,

                "title": "High memory usage linked to processes",

                "reason": [
                    f"System memory usage is {memory_usage}%",
                    "One or more processes account for significant memory usage"
                ],

                "related_processes": memory_processes
            })

    # ============================================================
    # SERVICE + LOG CORRELATION
    # ============================================================

    failed_services = (
        data["services"]["failed_services"]["stdout"]
    )

    log_errors = (
        data["logs"]["errors"]["stdout"]
    )

    if failed_services.strip() and log_errors.strip():

        correlations.append({

            "id": "service_log_correlation",

            "severity": "critical",

            "confidence": 0.96,

            "title": "Failed service supported by error logs",

            "reason": [
                "One or more services are failed",
                "Journal contains error-level events"
            ],

            "failed_services": (
                failed_services.splitlines()
            )
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
    # AI WORKLOAD + RESOURCE CORRELATION
    # ============================================================

    if cpu_usage >= 75:

        ai_processes = []

        for process in top_cpu[:5]:

            command = process.get(
                "command",
                ""
            ).lower()

            if any(
                keyword in command
                for keyword in [
                    "ollama",
                    "llama-server",
                    "llama",
                    "qwen",
                    "python"
                ]
            ):

                ai_processes.append({

                    "pid": process["pid"],

                    "command": process["command"],

                    "cpu_percent": process["cpu_percent"]
                })

        if ai_processes:

            correlations.append({

                "id": "ai_workload_cpu_correlation",

                "severity": "warning",

                "confidence": 0.88,

                "title": "High CPU usage associated with AI workload",

                "reason": [
                    f"Overall CPU usage is {cpu_usage}%",
                    "An AI-related process is among the highest CPU consumers"
                ],

                "related_processes": ai_processes
            })

    # ============================================================
    # RETURN CORRELATIONS
    # ============================================================

    return correlations