"""
NOVA — Unit tests for deterministic rule engine.

All tests use synthetic data dictionaries.
No live system calls (no /proc, systemctl, journalctl, ping, DNS, etc.)
Tests must pass offline and deterministically.
"""

import sys
import os
import unittest

# Allow running from project root without installing the package
sys.path.insert(
    0,
    os.path.dirname(
        os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))
        )
    )
)

from backend.diagnosis.rules import (
    check_cpu,
    check_memory,
    check_disk,
    check_processes,
    check_services,
)

from backend.diagnosis.service_classifier import (
    classify_service,
    parse_failed_services,
)

from backend.diagnosis.storage_intelligence import (
    analyze_storage,
)

from backend.diagnosis.log_intelligence import (
    build_log_intelligence,
)


# ============================================================
# SYNTHETIC DATA HELPERS
# ============================================================

def make_cpu(
    cpu_count=12,
    usage_percent=2.0,
    load1=0.5,
    load5=0.4,
    load15=0.3,
):
    return {
        "cpu_count": cpu_count,
        "usage_percent": usage_percent,
        "load1": load1,
        "load5": load5,
        "load15": load15,
    }


def make_memory(
    total_mb=16000,
    used_mb=5000,
    available_mb=11000,
    usage_percent=31.0,
    swap_total_mb=4096,
    swap_used_mb=0,
    swap_usage_percent=0.0,
):
    return {
        "memory": {
            "total_mb": total_mb,
            "used_mb": used_mb,
            "available_mb": available_mb,
            "usage_percent": usage_percent,
        },
        "swap": {
            "total_mb": swap_total_mb,
            "used_mb": swap_used_mb,
            "usage_percent": swap_usage_percent,
        },
    }


def make_disk(usage_percent=45, available_kb=50_000_000):
    return {
        "filesystem": "/dev/sda1",
        "total_kb": 100_000_000,
        "used_kb": 100_000_000 - available_kb,
        "available_kb": available_kb,
        "usage_percent": usage_percent,
    }


def make_process(
    pid=1001,
    command="some-process",
    cpu_percent=10.0,
    memory_percent=1.0,
    rss_kb=50000,
    state="S",
    elapsed="01:00:00",
    user="user",
    ppid=1,
):
    return {
        "pid": pid,
        "ppid": ppid,
        "user": user,
        "cpu_percent": cpu_percent,
        "memory_percent": memory_percent,
        "rss_kb": rss_kb,
        "state": state,
        "elapsed": elapsed,
        "command": command,
    }


def make_processes(top_cpu=None, top_memory=None):
    return {
        "top_cpu": top_cpu or [],
        "top_memory": top_memory or [],
    }


def make_services(failed_stdout="", running_stdout=""):
    return {
        "failed_services": {
            "stdout": failed_stdout,
            "stderr": "",
            "return_code": 0 if not failed_stdout else 1,
        },
        "running_services": {
            "stdout": running_stdout,
            "stderr": "",
            "return_code": 0,
        },
    }


def make_logs(error_stdout="", warning_stdout=""):
    return {
        "errors": {
            "stdout": error_stdout,
            "stderr": "",
            "return_code": 0,
        },
        "warnings": {
            "stdout": warning_stdout,
            "stderr": "",
            "return_code": 0,
        },
    }


def make_data(
    cpu=None,
    memory=None,
    disk=None,
    processes=None,
    services=None,
    logs=None,
):
    return {
        "cpu": cpu or make_cpu(),
        "memory": memory or make_memory(),
        "disk": disk or make_disk(),
        "processes": processes or make_processes(),
        "services": services or make_services(),
        "logs": logs or make_logs(),
    }


# ============================================================
# TEST 1
# 12-core system, CPU = 2%, llama-server = 167%
# Expected: NO system CPU anomaly from check_cpu()
# ============================================================

class TestCPU(unittest.TestCase):

    def test_low_system_cpu_no_anomaly(self):
        """
        TEST 1: System CPU is 2%, llama-server uses 167%.
        check_cpu() operates on system-wide usage only.
        2% must NOT produce a CPU anomaly.
        """
        data = make_data(
            cpu=make_cpu(cpu_count=12, usage_percent=2.0)
        )
        findings = check_cpu(data)
        assert findings == [], (
            f"Expected no CPU findings for 2% system CPU, got: {findings}"
        )

    def test_high_system_cpu_saturation(self):
        """
        TEST 2: System CPU = 95%, multiple heavy processes.
        Should produce cpu_saturation (critical).
        """
        data = make_data(
            cpu=make_cpu(cpu_count=12, usage_percent=95.0)
        )
        findings = check_cpu(data)
        assert any(
            f["id"] == "cpu_saturation" and f["severity"] == "critical"
            for f in findings
        ), f"Expected cpu_saturation critical, got: {findings}"

    def test_elevated_cpu_warning(self):
        """
        System CPU = 80% should produce warning, not critical.
        """
        data = make_data(
            cpu=make_cpu(usage_percent=80.0)
        )
        findings = check_cpu(data)
        assert any(
            f["id"] == "high_cpu" and f["severity"] == "warning"
            for f in findings
        ), f"Expected high_cpu warning, got: {findings}"

    def test_process_cpu_with_low_system_cpu_stays_warning(self):
        """
        llama-server = 167% (1.67 cores), system CPU = 2%.
        check_processes() should classify this as warning, not critical.
        (Critical only when system_pressure >= 75% AND cores >= 2.)
        """
        processes = make_processes(
            top_cpu=[
                make_process(
                    pid=1234,
                    command="llama-server",
                    cpu_percent=167.0,
                    elapsed="01:00:00",
                )
            ]
        )
        data = make_data(
            cpu=make_cpu(cpu_count=12, usage_percent=2.0),
            processes=processes,
        )
        findings = check_processes(data)
        assert findings, "Expected a process finding"
        for f in findings:
            assert f["severity"] == "warning", (
                f"Expected warning for llama-server with low system CPU, got {f['severity']}"
            )


# ============================================================
# TEST 3 & 4 — Memory pressure
# ============================================================

class TestMemory(unittest.TestCase):

    def test_critical_memory_pressure(self):
        """
        TEST 3: Memory 95%, available 300 MB, swap 90%.
        Should produce severe memory pressure (critical).
        """
        data = make_data(
            memory=make_memory(
                total_mb=16000,
                used_mb=15200,
                available_mb=300,
                usage_percent=95.0,
                swap_total_mb=4096,
                swap_used_mb=3686,
                swap_usage_percent=90.0,
            )
        )
        findings = check_memory(data)
        assert any(
            f["id"] == "memory_pressure" and f["severity"] == "critical"
            for f in findings
        ), f"Expected critical memory_pressure, got: {findings}"

    def test_no_memory_pressure_when_available_large(self):
        """
        TEST 4: Memory 90%, available 3000 MB, swap 0%.
        High percent but plenty of available memory — NOT a pressure anomaly.
        check_memory() must not fire high_memory when available >= 1024 MB.
        """
        data = make_data(
            memory=make_memory(
                total_mb=32000,
                used_mb=28800,
                available_mb=3000,
                usage_percent=90.0,
                swap_total_mb=4096,
                swap_used_mb=0,
                swap_usage_percent=0.0,
            )
        )
        findings = check_memory(data)
        # memory_pressure requires swap >= 50% AND memory >= 90%, but here swap=0%
        # high_memory requires available < 1024 — fails at 3000 MB
        assert not any(
            f["id"] in ("memory_pressure", "high_memory")
            for f in findings
        ), f"Expected no memory pressure for 3000 MB available, got: {findings}"

    def test_high_memory_fires_with_low_available(self):
        """
        Memory 88%, available 512 MB — should produce high_memory warning.
        """
        data = make_data(
            memory=make_memory(
                total_mb=8000,
                used_mb=7000,
                available_mb=512,
                usage_percent=88.0,
                swap_total_mb=2048,
                swap_used_mb=0,
                swap_usage_percent=0.0,
            )
        )
        findings = check_memory(data)
        assert any(
            f["id"] == "high_memory" and f["severity"] == "warning"
            for f in findings
        ), f"Expected high_memory warning at 512 MB available, got: {findings}"


# ============================================================
# TEST 7 — Storage observation
# ============================================================

class TestStorage(unittest.TestCase):

    def test_large_ollama_model_is_observation_not_anomaly(self):
        """
        TEST 7: Large Ollama model file.
        analyze_storage() must classify it as 'ai_model',
        set large=True, and deletion_recommended=False.
        """
        storage_data = {
            "scan_root": "/",
            "top_directories": [],
            "large_files": [
                {
                    "path": "/home/user/.ollama/models/blobs/sha256-abc123",
                    "size_bytes": 5_200_000_000,   # 5.2 GB
                    "size_human": "5.20 GB",
                }
            ],
            "policy": {
                "read_only": True,
                "deletion_performed": False,
                "excluded_paths": [],
            },
        }

        result = analyze_storage(storage_data)

        assert result["policy"]["read_only"] is True
        assert result["policy"]["deletion_recommended"] is False

        files = result["large_files"]
        assert files, "Expected at least one large file observation"

        model_file = files[0]
        assert model_file["classification"] == "ai_model", (
            f"Expected ai_model, got {model_file['classification']}"
        )
        assert model_file["large"] is True
        assert model_file["deletion_recommended"] is False


# ============================================================
# TEST 8 — Log observation: ACPI errors alone
# ============================================================

class TestLogIntelligence(unittest.TestCase):

    def test_acpi_errors_are_observations_only(self):
        """
        TEST 8: ACPI errors in the journal.
        They must be classified as 'acpi' category observations.
        The log intelligence layer must NOT produce findings itself.
        (Findings only come from rules.py / correlation.py.)
        """
        acpi_log = (
            "Aug 21 12:00:00 host kernel: ACPI BIOS Error (bug): "
            "Could not resolve symbol [\\_SB.PCI0.XHC.RHUB.HS04], "
            "AE_NOT_FOUND (20230628/dswload2-162)\n"
            "Aug 21 12:00:01 host kernel: ACPI Error: "
            "AE_NOT_FOUND, During name lookup/catalog "
            "(20230628/psobject-220)\n"
        )

        log_data = make_logs(error_stdout=acpi_log)

        result = build_log_intelligence(log_data)

        # log_intelligence never produces findings, only observations
        assert "groups" in result["errors"]

        categories = [
            g["category"]
            for g in result["errors"]["groups"]
        ]

        assert "acpi" in categories, (
            f"Expected ACPI category in log groups, got: {categories}"
        )

        # Policy must state that logs alone are not proof
        assert result["policy"]["logs_alone_do_not_confirm_system_failure"]


# ============================================================
# TEST 10 & 11 — Service tier classification
# ============================================================

class TestServiceClassifier(unittest.TestCase):

    def test_ollama_service_is_optional_warning_not_critical(self):
        """
        TEST 10: ollama.service failed → warning (optional_system).
        Must NOT be classified as critical.
        """
        result = classify_service("ollama.service")
        assert result["tier"] == "optional_system", (
            f"Expected optional_system, got {result['tier']}"
        )
        assert result["severity"] == "warning", (
            f"Expected warning, got {result['severity']}"
        )

    def test_network_manager_is_critical(self):
        """
        TEST 11: NetworkManager.service failed → critical (critical_system).
        """
        result = classify_service("NetworkManager.service")
        assert result["tier"] == "critical_system", (
            f"Expected critical_system, got {result['tier']}"
        )
        assert result["severity"] == "critical", (
            f"Expected critical, got {result['severity']}"
        )

    def test_systemd_journald_is_critical(self):
        result = classify_service("systemd-journald.service")
        assert result["tier"] == "critical_system"
        assert result["severity"] == "critical"

    def test_cups_is_optional(self):
        result = classify_service("cups.service")
        assert result["tier"] == "optional_system"
        assert result["severity"] == "warning"

    def test_docker_is_development(self):
        result = classify_service("docker.service")
        assert result["tier"] == "development"
        assert result["severity"] == "info"

    def test_snap_app_is_user_application(self):
        result = classify_service("snap.firefox.firefox.service")
        assert result["tier"] == "user_application"
        assert result["severity"] == "warning"

    def test_unknown_service_is_warning(self):
        result = classify_service("my-custom-obscure-daemon.service")
        assert result["tier"] == "unknown"
        assert result["severity"] == "warning"


class TestServiceRulesIntegration(unittest.TestCase):

    def test_check_services_ollama_produces_warning(self):
        """
        TEST 10 (rules integration):
        ollama.service in --failed output → check_services returns warning finding.
        """
        failed_output = (
            "  ollama.service  loaded failed failed  Manage Ollama model server"
        )
        data = make_data(
            services=make_services(failed_stdout=failed_output)
        )
        findings = check_services(data)
        assert findings, "Expected at least one finding"

        ollama_findings = [
            f for f in findings
            if "ollama" in f.get("service_name", "").lower()
        ]
        assert ollama_findings, "Expected a finding for ollama.service"

        f = ollama_findings[0]
        assert f["severity"] == "warning", (
            f"Expected warning for ollama.service, got {f['severity']}"
        )
        assert f["service_tier"] == "optional_system"

    def test_check_services_networkmanager_produces_critical(self):
        """
        TEST 11 (rules integration):
        NetworkManager.service in --failed output → critical finding.
        """
        failed_output = (
            "  NetworkManager.service  loaded failed failed  Network Manager"
        )
        data = make_data(
            services=make_services(failed_stdout=failed_output)
        )
        findings = check_services(data)
        assert findings, "Expected at least one finding"

        nm_findings = [
            f for f in findings
            if "NetworkManager" in f.get("service_name", "")
        ]
        assert nm_findings, "Expected a finding for NetworkManager.service"

        f = nm_findings[0]
        assert f["severity"] == "critical", (
            f"Expected critical for NetworkManager.service, got {f['severity']}"
        )
        assert f["service_tier"] == "critical_system"


class TestParseFailedServices(unittest.TestCase):

    def test_parse_basic_failed_line(self):
        output = (
            "  ollama.service  loaded failed failed  Manage Ollama model server\n"
            "  bluetooth.service  loaded failed failed  Bluetooth service\n"
        )
        names = parse_failed_services(output)
        assert "ollama.service" in names
        assert "bluetooth.service" in names

    def test_parse_with_bullet(self):
        output = "● NetworkManager.service  loaded failed failed  Network Manager\n"
        names = parse_failed_services(output)
        assert "NetworkManager.service" in names

    def test_parse_empty_output(self):
        names = parse_failed_services("")
        assert names == []


if __name__ == "__main__":
    unittest.main()
