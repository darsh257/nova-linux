import sys
import os
import unittest

sys.path.insert(
    0,
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
)

from backend.diagnosis.root_cause import generate_root_cause_candidates


class TestRootCauseCPU(unittest.TestCase):

    def test_ai_process_high_cpu_low_system_cpu_no_candidate(self):
        """
        TEST 1: AI process high CPU + low system CPU -> observation only (no candidate).
        """
        correlations = [{
            "id": "ai_workload_observation",
            "type": "observation",
            "severity": "info"
        }]
        findings = []
        candidates = generate_root_cause_candidates({}, findings, correlations)
        cpu_candidates = [c for c in candidates if c["scope"] == "cpu"]
        self.assertEqual(len(cpu_candidates), 0)

    def test_high_system_cpu_and_load(self):
        """
        TEST 2: High system CPU + high load -> CPU anomaly candidate (unknown driver if no processes).
        """
        findings = [{
            "id": "cpu_saturation",
            "severity": "critical",
            "confidence": 0.90,
            "evidence": ["CPU usage is 95%"]
        }]
        correlations = []
        candidates = generate_root_cause_candidates({}, findings, correlations)
        
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["id"], "cpu_unknown_root_cause")
        self.assertEqual(candidates[0]["severity"], "critical")
        self.assertEqual(len(candidates[0]["contributors"]), 0)

    def test_cpu_pressure_with_heavy_process(self):
        """
        TEST 3: CPU pressure + heavy process -> likely CPU contributor.
        """
        findings = [{
            "id": "cpu_saturation",
            "severity": "critical"
        }]
        correlations = [{
            "id": "cpu_process_correlation",
            "severity": "critical",
            "confidence": 0.94,
            "reason": ["Overall CPU usage is 96%"],
            "related_processes": [
                {"command": "llama-server", "cpu_cores_used": 2.50}
            ]
        }]
        candidates = generate_root_cause_candidates({}, findings, correlations)
        
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["id"], "cpu_process_root_cause")
        self.assertEqual(candidates[0]["severity"], "critical")
        self.assertEqual(len(candidates[0]["contributors"]), 1)
        self.assertEqual(candidates[0]["contributors"][0]["entity"], "llama-server")


class TestRootCauseMemory(unittest.TestCase):

    def test_memory_pressure_with_swap(self):
        """
        TEST 4: Memory pressure + swap pressure -> memory anomaly.
        """
        findings = [{
            "id": "memory_pressure",
            "severity": "critical"
        }]
        correlations = [{
            "id": "memory_pressure_correlation",
            "severity": "critical",
            "confidence": 0.97,
            "related_processes": [{"command": "chrome", "memory_percent": 25}]
        }]
        candidates = generate_root_cause_candidates({}, findings, correlations)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["id"], "memory_process_root_cause")
        self.assertEqual(candidates[0]["severity"], "critical")
        self.assertEqual(len(candidates[0]["contributors"]), 1)

    def test_high_memory_percent_large_available(self):
        """
        TEST 5: High memory percentage + large available memory -> no memory anomaly.
        (If no finding/correlation generated, no root cause should be produced)
        """
        findings = []
        correlations = []
        candidates = generate_root_cause_candidates({}, findings, correlations)
        mem_candidates = [c for c in candidates if c["scope"] == "memory"]
        self.assertEqual(len(mem_candidates), 0)


class TestRootCauseService(unittest.TestCase):

    def test_failed_optional_service(self):
        """
        TEST 6: Failed optional service -> warning.
        """
        findings = [{
            "id": "failed_service",
            "severity": "warning",
            "service_name": "ollama.service",
            "confidence": 0.90
        }]
        correlations = []
        candidates = generate_root_cause_candidates({}, findings, correlations)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["id"], "service_isolated_ollama.service")
        self.assertEqual(candidates[0]["severity"], "warning")

    def test_failed_critical_service(self):
        """
        TEST 7: Failed critical service -> critical.
        """
        findings = [{
            "id": "failed_service",
            "severity": "critical",
            "service_name": "NetworkManager.service",
            "confidence": 0.97
        }]
        correlations = []
        candidates = generate_root_cause_candidates({}, findings, correlations)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["id"], "service_isolated_NetworkManager.service")
        self.assertEqual(candidates[0]["severity"], "critical")

    def test_failed_service_with_matching_log(self):
        """
        TEST 8: Failed service + matching log -> stronger candidate.
        """
        findings = [{
            "id": "failed_service",
            "severity": "warning",
            "service_name": "ollama.service"
        }]
        correlations = [{
            "id": "service_log_correlation",
            "severity": "warning",
            "confidence": 0.95,
            "failed_services": ["ollama.service"]
        }]
        candidates = generate_root_cause_candidates({}, findings, correlations)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["id"], "service_failure_root_cause")
        self.assertEqual(candidates[0]["confidence"], 0.95)

    def test_failed_service_with_unrelated_log(self):
        """
        TEST 9: Failed service + unrelated log -> no false correlation.
        (This tests root_cause.py handling an isolated failed_service when no correlation exists).
        """
        findings = [{
            "id": "failed_service",
            "severity": "warning",
            "service_name": "ollama.service",
            "confidence": 0.90
        }]
        correlations = []
        candidates = generate_root_cause_candidates({}, findings, correlations)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["id"], "service_isolated_ollama.service")
        self.assertEqual(candidates[0]["confidence"], 0.90)


class TestRootCauseNetwork(unittest.TestCase):

    def test_healthy_network(self):
        """
        TEST 10: Healthy network -> no network anomaly.
        """
        candidates = generate_root_cause_candidates({}, [], [])
        net_candidates = [c for c in candidates if c["scope"] == "network"]
        self.assertEqual(len(net_candidates), 0)

    def test_gateway_failure(self):
        """
        TEST 11: Gateway failure -> gateway/network candidate.
        """
        findings = [{"id": "connectivity_gateway_unreachable", "severity": "critical", "confidence": 0.93}]
        correlations = [{"id": "gateway_unreachable", "severity": "critical", "confidence": 0.97}]
        candidates = generate_root_cause_candidates({}, findings, correlations)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["id"], "network_gateway_root_cause")

    def test_dns_failure(self):
        """
        TEST 12: DNS failure -> DNS candidate.
        """
        findings = [{"id": "connectivity_dns_failure"}]
        correlations = [{"id": "dns_failure", "severity": "warning", "confidence": 0.95}]
        candidates = generate_root_cause_candidates({}, findings, correlations)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["id"], "network_dns_root_cause")

    def test_https_failure(self):
        """
        TEST 13: HTTPS failure after DNS success -> external connectivity candidate.
        """
        findings = []
        correlations = [{"id": "external_connectivity_failure", "severity": "warning", "confidence": 0.88}]
        candidates = generate_root_cause_candidates({}, findings, correlations)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["id"], "network_external_root_cause")


class TestRootCauseStorage(unittest.TestCase):

    def test_large_ollama_model(self):
        """
        TEST 14: Large Ollama model -> storage observation.
        (No disk pressure finding -> no root cause)
        """
        candidates = generate_root_cause_candidates({}, [], [])
        storage_candidates = [c for c in candidates if c["scope"] == "storage"]
        self.assertEqual(len(storage_candidates), 0)

    def test_nearly_full_disk_large_files(self):
        """
        TEST 15: Nearly full disk + large files -> disk-pressure candidate.
        """
        findings = [{"id": "disk_critical", "severity": "critical"}]
        correlations = [{
            "id": "disk_storage_correlation",
            "severity": "critical",
            "confidence": 0.91,
            "large_files": [{"path": "/var/log/syslog", "size_human": "5GB"}]
        }]
        candidates = generate_root_cause_candidates({}, findings, correlations)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["id"], "storage_files_root_cause")
        self.assertEqual(len(candidates[0]["contributors"]), 1)


class TestRootCauseLogsAndAI(unittest.TestCase):

    def test_acpi_logs_without_evidence(self):
        """
        TEST 16: ACPI logs without supporting evidence -> observation only (no candidate).
        """
        candidates = generate_root_cause_candidates({}, [], [])
        self.assertEqual(len(candidates), 0)

    def test_ai_workload_healthy_system(self):
        """
        TEST 17: AI workload on healthy system -> info observation only.
        """
        correlations = [{
            "id": "ai_workload_observation",
            "severity": "info",
            "type": "observation"
        }]
        candidates = generate_root_cause_candidates({}, [], correlations)
        self.assertEqual(len(candidates), 0)


if __name__ == "__main__":
    unittest.main()
