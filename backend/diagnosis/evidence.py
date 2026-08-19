def build_evidence(data, findings, correlations):

    memory = data["memory"]["memory"]
    swap = data["memory"]["swap"]
    cpu = data["cpu"]
    disk = data["disk"]

    top_cpu = data["processes"]["top_cpu"]
    top_memory = data["processes"]["top_memory"]

    return {
        "system_state": {
            "cpu": {
                "cpu_count": cpu["cpu_count"],
                "usage_percent": cpu["usage_percent"]
            },

            "memory": {
                "total_mb": memory["total_mb"],
                "used_mb": memory["used_mb"],
                "available_mb": memory["available_mb"],
                "usage_percent": memory["usage_percent"]
            },

            "swap": {
                "total_mb": swap["total_mb"],
                "used_mb": swap["used_mb"],
                "usage_percent": swap["usage_percent"]
            },

            "disk": {
                "filesystem": disk["filesystem"],
                "usage_percent": disk["usage_percent"],
                "available_kb": disk["available_kb"]
            }
        },

        "top_cpu_processes": [
            {
                "pid": p["pid"],
                "command": p["command"],
                "cpu_percent": p["cpu_percent"],
                "memory_percent": p["memory_percent"]
            }
            for p in top_cpu[:5]
        ],

        "top_memory_processes": [
            {
                "pid": p["pid"],
                "command": p["command"],
                "cpu_percent": p["cpu_percent"],
                "memory_percent": p["memory_percent"]
            }
            for p in top_memory[:5]
        ],

        "findings": findings,

        "correlations": correlations,

        "services": {
            "failed": data["services"]["failed_services"]["stdout"],
            "running": data["services"]["running_services"]["stdout"]
        },

        "logs": {
            "errors": data["logs"]["errors"]["stdout"],
            "warnings": data["logs"]["warnings"]["stdout"]
        }
    }
