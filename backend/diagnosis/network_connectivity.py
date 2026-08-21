import re
import socket
import subprocess


def run_command(command, timeout=5):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout
        )

        return {
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "return_code": result.returncode
        }

    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": "Command timed out",
            "return_code": -1
        }

    except Exception as exc:
        return {
            "stdout": "",
            "stderr": str(exc),
            "return_code": -1
        }


def get_default_route(network_data):
    routes = network_data.get("routes", {})
    output = routes.get("stdout", "") if isinstance(routes, dict) else ""

    for line in output.splitlines():

        line = line.strip()

        if not line.startswith("default "):
            continue

        gateway_match = re.search(
            r"default via ([^\s]+)",
            line
        )

        interface_match = re.search(
            r"\bdev ([^\s]+)",
            line
        )

        return {
            "route": line,
            "gateway": (
                gateway_match.group(1)
                if gateway_match
                else None
            ),
            "interface": (
                interface_match.group(1)
                if interface_match
                else None
            )
        }

    return None


def get_active_interface(network_data):
    interfaces = network_data.get("interfaces", {})
    output = (
        interfaces.get("stdout", "")
        if isinstance(interfaces, dict)
        else ""
    )

    for line in output.splitlines():

        parts = line.split()

        if len(parts) < 2:
            continue

        name = parts[0]
        state = parts[1]

        if name == "lo":
            continue

        if state != "UP":
            continue

        addresses = [
            value
            for value in parts[2:]
            if "/" in value
        ]

        return {
            "name": name,
            "state": state,
            "addresses": addresses
        }

    return None


def check_gateway(gateway):
    if not gateway:
        return {
            "tested": False,
            "reachable": None,
            "reason": "No gateway was detected"
        }

    result = run_command(
        [
            "ping",
            "-c",
            "1",
            "-W",
            "2",
            gateway
        ],
        timeout=4
    )

    return {
        "tested": True,
        "gateway": gateway,
        "reachable": result["return_code"] == 0,
        "return_code": result["return_code"],
        "stdout": result["stdout"],
        "stderr": result["stderr"]
    }


def check_dns():

    result = run_command(
        [
            "getent",
            "ahostsv4",
            "example.com"
        ],
        timeout=5
    )

    resolved = result["return_code"] == 0 and bool(
        result["stdout"].strip()
    )

    return {
        "tested": True,
        "resolved": resolved,
        "return_code": result["return_code"],
        "stdout": result["stdout"],
        "stderr": result["stderr"]
    }


def check_external_connectivity():

    result = run_command(
        [
            "curl",
            "-I",
            "-L",
            "--max-time",
            "5",
            "--connect-timeout",
            "3",
            "https://example.com"
        ],
        timeout=7
    )

    reachable = result["return_code"] == 0

    return {
        "tested": True,
        "reachable": reachable,
        "return_code": result["return_code"],
        "stdout": result["stdout"],
        "stderr": result["stderr"]
    }


def build_findings(
    active_interface,
    default_route,
    gateway,
    dns,
    external
):

    findings = []

    # -------------------------------------------------
    # NO ACTIVE INTERFACE
    # -------------------------------------------------

    if not active_interface:

        findings.append({
            "id": "connectivity_no_interface",
            "severity": "critical",
            "confidence": 0.97,
            "title": "No active network interface",
            "evidence": [
                "No non-loopback network interface is UP"
            ]
        })

        return findings

    # -------------------------------------------------
    # ACTIVE INTERFACE WITHOUT IP
    # -------------------------------------------------

    if not active_interface["addresses"]:

        findings.append({
            "id": "connectivity_no_ip",
            "severity": "critical",
            "confidence": 0.95,
            "title": (
                f"Active interface "
                f"{active_interface['name']} has no IP address"
            ),
            "evidence": [
                f"Interface: {active_interface['name']}",
                "Interface state: UP",
                "No IP address detected"
            ]
        })

        return findings

    # -------------------------------------------------
    # NO DEFAULT ROUTE
    # -------------------------------------------------

    if not default_route:

        findings.append({
            "id": "connectivity_no_default_route",
            "severity": "warning",
            "confidence": 0.95,
            "title": "No default route",
            "evidence": [
                "Active network interface exists",
                "No default route exists"
            ]
        })

        return findings

    # -------------------------------------------------
    # GATEWAY UNREACHABLE
    # -------------------------------------------------

    if gateway["tested"] and not gateway["reachable"]:

        findings.append({
            "id": "connectivity_gateway_unreachable",
            "severity": "critical",
            "confidence": 0.93,
            "title": "Default gateway is unreachable",
            "evidence": [
                f"Gateway: {gateway['gateway']}",
                "Gateway ping failed"
            ]
        })

        return findings

    # -------------------------------------------------
    # DNS FAILURE
    # -------------------------------------------------

    if gateway["reachable"] and dns["tested"] and not dns["resolved"]:

        findings.append({
            "id": "connectivity_dns_failure",
            "severity": "warning",
            "confidence": 0.90,
            "title": "DNS resolution failed",
            "evidence": [
                "Default gateway is reachable",
                "DNS lookup failed"
            ]
        })

        return findings

    # -------------------------------------------------
    # EXTERNAL CONNECTIVITY FAILURE
    # -------------------------------------------------

    if (
        gateway["reachable"]
        and dns["resolved"]
        and external["tested"]
        and not external["reachable"]
    ):

        findings.append({
            "id": "connectivity_external_failure",
            "severity": "warning",
            "confidence": 0.88,
            "title": "External network connectivity failed",
            "evidence": [
                "Default gateway is reachable",
                "DNS resolution succeeds",
                "External HTTPS connectivity failed"
            ]
        })

    return findings


def analyze_connectivity(network_data):

    active_interface = get_active_interface(
        network_data
    )

    default_route = get_default_route(
        network_data
    )

    gateway = check_gateway(
        default_route["gateway"]
        if default_route
        else None
    )

    dns = check_dns()

    external = check_external_connectivity()

    findings = build_findings(
        active_interface,
        default_route,
        gateway,
        dns,
        external
    )

    return {

        "connectivity_state": {

            "active_interface": active_interface,

            "default_route": default_route,

            "gateway": gateway,

            "dns": dns,

            "external_connectivity": external
        },

        "findings": findings,

        "policy": {

            "read_only": True,

            "network_changes_performed": False,

            "gateway_test_is_icmp_only": True,

            "dns_test_is_resolution_only": True,

            "external_test_uses_https": True,

            "no_configuration_changes": True
        }
    }


if __name__ == "__main__":

    import json

    from backend.core import collect_system_info

    data = collect_system_info()

    result = analyze_connectivity(
        data["network"]
    )

    print(
        json.dumps(
            result,
            indent=2
        )
    )
