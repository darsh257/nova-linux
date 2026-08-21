def _get_stdout(network_data, key):
    section = network_data.get(key, {})

    if isinstance(section, dict):
        return section.get("stdout", "") or ""

    return ""


def _parse_interfaces(network_data):

    output = _get_stdout(
        network_data,
        "interfaces"
    )

    interfaces = []

    for line in output.splitlines():

        parts = line.split()

        if len(parts) < 2:
            continue

        name = parts[0]
        state = parts[1]

        addresses = []

        for value in parts[2:]:

            if "/" in value:
                addresses.append(value)

        interfaces.append({
            "name": name,
            "state": state,
            "addresses": addresses
        })

    return interfaces


def _parse_routes(network_data):

    output = _get_stdout(
        network_data,
        "routes"
    )

    routes = []

    for line in output.splitlines():

        line = line.strip()

        if line:
            routes.append(line)

    return routes


def _parse_connections(network_data):

    output = _get_stdout(
        network_data,
        "connections"
    )

    connections = []

    for line in output.splitlines():

        line = line.strip()

        if not line:
            continue

        connections.append(line)

    return connections


def _is_loopback(interface):

    return interface["name"] == "lo"


def _has_ip_address(interface):

    return len(interface["addresses"]) > 0


def _interface_findings(interfaces):

    findings = []

    physical_or_virtual_interfaces = []

    active_interfaces = []

    for interface in interfaces:

        name = interface["name"]
        state = interface["state"]

        # -----------------------------------------
        # LOOPBACK
        # -----------------------------------------

        if _is_loopback(interface):

            continue

        physical_or_virtual_interfaces.append(
            interface
        )

        # -----------------------------------------
        # ACTIVE INTERFACE
        # -----------------------------------------

        if state == "UP":

            active_interfaces.append(
                interface
            )

            continue

        # -----------------------------------------
        # DOWN INTERFACE
        # -----------------------------------------

        if state == "DOWN":

            # A DOWN interface is not automatically
            # an anomaly. It may simply be unused.
            continue

    # -----------------------------------------
    # NO ACTIVE NETWORK INTERFACE
    # -----------------------------------------

    if not active_interfaces:

        findings.append({
            "id": "no_active_network_interface",
            "severity": "critical",
            "confidence": 0.95,
            "title": "No active network interface detected",
            "evidence": [
                "No non-loopback network interface is UP"
            ]
        })

    # -----------------------------------------
    # ACTIVE INTERFACE WITHOUT ADDRESS
    # -----------------------------------------

    for interface in active_interfaces:

        if not _has_ip_address(interface):

            findings.append({
                "id": "active_interface_without_address",
                "severity": "warning",
                "confidence": 0.90,
                "title": (
                    f"Active network interface "
                    f"{interface['name']} has no IP address"
                ),
                "evidence": [
                    f"Interface: {interface['name']}",
                    f"State: {interface['state']}",
                    "No IP address detected"
                ],
                "interface": interface
            })

    return findings


def _route_findings(routes):

    findings = []

    default_routes = [
        route
        for route in routes
        if route.startswith("default ")
    ]

    if not default_routes:

        findings.append({
            "id": "missing_default_route",
            "severity": "warning",
            "confidence": 0.90,
            "title": "No default network route detected",
            "evidence": [
                "The routing table contains no default route"
            ]
        })

    return findings


def _connection_analysis(connections):

    listening_connections = []

    for connection in connections:

        if "LISTEN" in connection:
            listening_connections.append(
                connection
            )

    return {
        "total_connections": len(connections),

        "listening_socket_count": len(
            listening_connections
        ),

        "listening_sockets": listening_connections
    }


def analyze_network(network_data):

    interfaces = _parse_interfaces(
        network_data
    )

    routes = _parse_routes(
        network_data
    )

    connections = _parse_connections(
        network_data
    )

    findings = []

    findings.extend(
        _interface_findings(
            interfaces
        )
    )

    findings.extend(
        _route_findings(
            routes
        )
    )

    connection_analysis = _connection_analysis(
        connections
    )

    active_interfaces = [
        interface
        for interface in interfaces
        if (
            interface["state"] == "UP"
            and not _is_loopback(interface)
        )
    ]

    default_routes = [
        route
        for route in routes
        if route.startswith("default ")
    ]

    return {

        "interfaces": interfaces,

        "routes": routes,

        "connections": connections,

        "network_state": {

            "interface_count": len(
                interfaces
            ),

            "active_interface_count": len(
                active_interfaces
            ),

            "default_route_count": len(
                default_routes
            ),

            "listening_socket_count":
                connection_analysis[
                    "listening_socket_count"
                ]
        },

        "findings": findings,

        "policy": {

            "read_only": True,

            "network_changes_performed": False,

            "loopback_state_not_treated_as_failure": True,

            "unused_down_interfaces_not_treated_as_failure": True,

            "interface_state_alone_does_not_prove_internet_connectivity": True,

            "default_route_required_for_normal_external_connectivity": True,

            "listening_socket_alone_does_not_prove_service_health": True
        }
    }


if __name__ == "__main__":

    import json

    from backend.core import collect_system_info

    data = collect_system_info()

    result = analyze_network(
        data["network"]
    )

    print(
        json.dumps(
            result,
            indent=2
        )
    )
