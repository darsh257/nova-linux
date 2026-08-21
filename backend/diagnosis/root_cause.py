def generate_root_cause_candidates(data, findings, correlations):
    """
    Generate deterministic root-cause candidates from existing findings
    and correlations. Candidates are structured explanations of what
    is likely causing the detected anomalies.
    """
    candidates = []

    # Fast lookups for existing findings/correlations by ID
    finding_ids = {f["id"]: f for f in findings}
    correlation_ids = {c["id"]: c for c in correlations}

    def add_candidate(c):
        candidates.append(c)

    # ============================================================
    # 1. CPU REASONING
    # ============================================================
    cpu_corr = correlation_ids.get("cpu_process_correlation")
    cpu_sat = finding_ids.get("cpu_saturation")
    
    if cpu_corr:
        add_candidate({
            "id": "cpu_process_root_cause",
            "title": "CPU pressure driven by heavy processes",
            "severity": cpu_corr.get("severity", "critical"),
            "confidence": cpu_corr.get("confidence", 0.92),
            "scope": "cpu",
            "evidence": cpu_corr.get("reason", []),
            "related_findings": ["cpu_saturation"] if cpu_sat else [],
            "related_correlations": ["cpu_process_correlation"],
            "contributors": [
                {
                    "entity": p.get("command"),
                    "reason": f"Likely contributor consuming {p.get('cpu_cores_used', 0)} CPU cores"
                }
                for p in cpu_corr.get("related_processes", [])
            ],
            "explanation": "High CPU utilization is likely caused by the listed processes."
        })
    elif cpu_sat:
        add_candidate({
            "id": "cpu_unknown_root_cause",
            "title": "CPU saturation with unknown driver",
            "severity": cpu_sat.get("severity", "critical"),
            "confidence": cpu_sat.get("confidence", 0.90),
            "scope": "cpu",
            "evidence": cpu_sat.get("evidence", []),
            "related_findings": ["cpu_saturation"],
            "related_correlations": [],
            "contributors": [],
            "explanation": "System is saturated but no single heavy process was identified."
        })

    # ============================================================
    # 2. MEMORY REASONING
    # ============================================================
    mem_corr = correlation_ids.get("memory_process_correlation")
    mem_press_corr = correlation_ids.get("memory_pressure_correlation")
    mem_pressure = finding_ids.get("memory_pressure")
    high_mem = finding_ids.get("high_memory")

    # Prefer the more severe correlation
    active_mem_corr = mem_press_corr or mem_corr
    active_mem_finding = mem_pressure or high_mem

    if active_mem_corr:
        add_candidate({
            "id": "memory_process_root_cause",
            "title": "Memory pressure driven by heavy processes",
            "severity": active_mem_corr.get("severity", "warning"),
            "confidence": active_mem_corr.get("confidence", 0.90),
            "scope": "memory",
            "evidence": active_mem_corr.get("reason", []),
            "related_findings": [active_mem_finding["id"]] if active_mem_finding else [],
            "related_correlations": [active_mem_corr["id"]],
            "contributors": [
                {
                    "entity": p.get("command"),
                    "reason": f"Likely contributor consuming {p.get('memory_percent', 0)}% memory"
                }
                for p in active_mem_corr.get("related_processes", [])
            ],
            "explanation": "Memory pressure is likely caused by the listed processes."
        })
    elif active_mem_finding:
        add_candidate({
            "id": "memory_unknown_root_cause",
            "title": "Memory pressure with unknown driver",
            "severity": active_mem_finding.get("severity", "warning"),
            "confidence": active_mem_finding.get("confidence", 0.85),
            "scope": "memory",
            "evidence": active_mem_finding.get("evidence", []),
            "related_findings": [active_mem_finding["id"]],
            "related_correlations": [],
            "contributors": [],
            "explanation": "Memory is constrained but no specific heavy process was identified."
        })

    # ============================================================
    # 3. SERVICE REASONING
    # ============================================================
    svc_corr = correlation_ids.get("service_log_correlation")
    failed_svcs = [f for f in findings if f["id"] == "failed_service"]

    if svc_corr:
        # We have failed services backed by logs
        failed_names = svc_corr.get("failed_services", [])
        add_candidate({
            "id": "service_failure_root_cause",
            "title": "Service failure supported by logs",
            "severity": svc_corr.get("severity", "warning"),
            "confidence": svc_corr.get("confidence", 0.90),
            "scope": "service",
            "evidence": svc_corr.get("reason", []) + svc_corr.get("matching_log_lines", []),
            "related_findings": ["failed_service"],
            "related_correlations": ["service_log_correlation"],
            "contributors": [
                {
                    "entity": name,
                    "reason": "Failed service"
                }
                for name in failed_names
            ],
            "explanation": "Service failure is confirmed by matching errors in the journal log."
        })
    elif failed_svcs:
        # Isolated service failures
        for svc in failed_svcs:
            add_candidate({
                "id": f"service_isolated_{svc['service_name']}",
                "title": f"Service failure: {svc['service_name']}",
                "severity": svc.get("severity", "warning"),
                "confidence": svc.get("confidence", 0.75),
                "scope": "service",
                "evidence": svc.get("evidence", []),
                "related_findings": ["failed_service"],
                "related_correlations": [],
                "contributors": [
                    {
                        "entity": svc["service_name"],
                        "reason": "Failed service without supporting logs"
                    }
                ],
                "explanation": "Service is in a failed state, but no related logs were found."
            })

    # ============================================================
    # 4. NETWORK REASONING
    # ============================================================
    net_no_iface = correlation_ids.get("network_no_active_interface") or finding_ids.get("connectivity_no_interface") or finding_ids.get("no_active_network_interface")
    net_no_route = correlation_ids.get("network_missing_default_route") or finding_ids.get("connectivity_no_default_route") or finding_ids.get("missing_default_route")
    net_gw = correlation_ids.get("gateway_unreachable") or finding_ids.get("connectivity_gateway_unreachable")
    net_dns = correlation_ids.get("dns_failure") or finding_ids.get("connectivity_dns_failure")
    net_ext = correlation_ids.get("external_connectivity_failure") or finding_ids.get("connectivity_external_failure")

    if net_no_iface:
        add_candidate({
            "id": "network_interface_root_cause",
            "title": "No active network interface",
            "severity": net_no_iface.get("severity", "critical"),
            "confidence": net_no_iface.get("confidence", 0.95),
            "scope": "network",
            "evidence": net_no_iface.get("reason", []) or net_no_iface.get("evidence", []),
            "related_findings": ["connectivity_no_interface", "no_active_network_interface"],
            "related_correlations": ["network_no_active_interface"],
            "contributors": [],
            "explanation": "Network failure is caused by the lack of an active (UP) interface."
        })
    elif net_no_route:
        add_candidate({
            "id": "network_routing_root_cause",
            "title": "Missing default route",
            "severity": net_no_route.get("severity", "warning"),
            "confidence": net_no_route.get("confidence", 0.90),
            "scope": "network",
            "evidence": net_no_route.get("reason", []) or net_no_route.get("evidence", []),
            "related_findings": ["connectivity_no_default_route", "missing_default_route"],
            "related_correlations": ["network_missing_default_route"],
            "contributors": [],
            "explanation": "Network failure is caused by a missing default routing entry."
        })
    elif net_gw:
        add_candidate({
            "id": "network_gateway_root_cause",
            "title": "Local gateway unreachable",
            "severity": net_gw.get("severity", "critical"),
            "confidence": net_gw.get("confidence", 0.95),
            "scope": "network",
            "evidence": net_gw.get("reason", []) or net_gw.get("evidence", []),
            "related_findings": ["connectivity_gateway_unreachable"],
            "related_correlations": ["gateway_unreachable"],
            "contributors": [],
            "explanation": "Network failure occurs at the local gateway level."
        })
    elif net_dns:
        add_candidate({
            "id": "network_dns_root_cause",
            "title": "DNS resolution failure",
            "severity": net_dns.get("severity", "warning"),
            "confidence": net_dns.get("confidence", 0.90),
            "scope": "network",
            "evidence": net_dns.get("reason", []) or net_dns.get("evidence", []),
            "related_findings": ["connectivity_dns_failure"],
            "related_correlations": ["dns_failure"],
            "contributors": [],
            "explanation": "Network failure is caused by DNS resolution problems."
        })
    elif net_ext:
        add_candidate({
            "id": "network_external_root_cause",
            "title": "External connectivity failure",
            "severity": net_ext.get("severity", "warning"),
            "confidence": net_ext.get("confidence", 0.88),
            "scope": "network",
            "evidence": net_ext.get("reason", []) or net_ext.get("evidence", []),
            "related_findings": ["connectivity_external_failure"],
            "related_correlations": ["external_connectivity_failure"],
            "contributors": [],
            "explanation": "Gateway and DNS work, but external HTTPS connectivity fails."
        })

    # ============================================================
    # 5. STORAGE REASONING
    # ============================================================
    disk_corr = correlation_ids.get("disk_storage_correlation")
    disk_crit = finding_ids.get("disk_critical")
    disk_press = finding_ids.get("disk_pressure")
    active_disk = disk_crit or disk_press

    if disk_corr:
        add_candidate({
            "id": "storage_files_root_cause",
            "title": "Disk pressure supported by large files",
            "severity": disk_corr.get("severity", "warning"),
            "confidence": disk_corr.get("confidence", 0.91),
            "scope": "storage",
            "evidence": disk_corr.get("reason", []),
            "related_findings": [active_disk["id"]] if active_disk else [],
            "related_correlations": ["disk_storage_correlation"],
            "contributors": [
                {
                    "entity": f.get("path"),
                    "reason": f"Likely contributor: {f.get('size_human')}"
                }
                for f in disk_corr.get("large_files", [])
            ],
            "explanation": "Disk pressure is likely contributed to by large files. These files should not be automatically deleted."
        })
    elif active_disk:
        add_candidate({
            "id": "storage_unknown_root_cause",
            "title": "Disk pressure with unknown driver",
            "severity": active_disk.get("severity", "warning"),
            "confidence": active_disk.get("confidence", 0.85),
            "scope": "storage",
            "evidence": active_disk.get("evidence", []),
            "related_findings": [active_disk["id"]],
            "related_correlations": [],
            "contributors": [],
            "explanation": "Disk is nearly full, but no specific large files were identified."
        })

    return candidates
