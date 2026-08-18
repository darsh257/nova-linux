def correlate(data, findings):

    correlations = []

    cpu_usage = data["cpu"]["usage_percent"]

    top_cpu = data["processes"]["top_cpu"]

    # -----------------------------------------
    # CPU SATURATION + PROCESS CORRELATION
    # -----------------------------------------

    if cpu_usage >= 80:

        heavy_processes = []

        for process in top_cpu[:5]:

            if process["cpu_percent"] >= 20:

                heavy_processes.append({
                    "pid": process["pid"],
                    "command": process["command"],
                    "cpu_percent": process["cpu_percent"]
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
                    f"Overall CPU usage is {cpu_usage}%"
                ],
                "related_processes": heavy_processes
            })

    # -----------------------------------------
    # MEMORY PRESSURE
    # -----------------------------------------

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

    # -----------------------------------------
    # SERVICE + LOG CORRELATION
    # -----------------------------------------

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
            ]
        })

    return correlations
