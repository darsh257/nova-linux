"""
NOVA Service Classifier

Classifies systemd services into diagnostic tiers.

This module is deterministic.
The AI model must not override these classifications.

Tiers
-----
critical_system
    Fundamental services whose failure directly impairs the OS or
    user sessions (init, dbus, network stack, device management, etc.)

optional_system
    System-level services that provide useful but non-essential
    functionality (printing, Bluetooth, time sync, mDNS, AI inference, etc.)

user_application
    User-installed or third-party application services (databases,
    web servers, media services, etc.)

development
    Development tooling services (Docker, VMs, language servers, etc.)

unknown
    Service cannot be matched to any known tier.
"""


# ============================================================
# TIER DEFINITIONS
# ============================================================

# Each set lists exact systemd unit names (without ".service").
# Prefix patterns are handled below.

CRITICAL_SYSTEM_SERVICES = {
    # systemd core
    "systemd-journald",
    "systemd-logind",
    "systemd-udevd",
    "systemd-networkd",
    "systemd-resolved",
    "systemd-timesyncd",

    # D-Bus — message bus for all desktop and system communication
    "dbus",
    "dbus-broker",

    # Network stack
    "NetworkManager",
    "network",
    "networking",
    "wpa_supplicant",

    # Authentication / authorisation
    "polkit",
    "pam",
    "sshd",
    "openssh-server",

    # Device / hardware management
    "udev",
    "udisksd",
    "upower",

    # Login / display manager
    "gdm",
    "gdm3",
    "lightdm",
    "sddm",
    "xdm",

    # Power / suspend management
    "logind",
    "acpid",

    # Boot / shutdown
    "plymouth",
    "plymouth-start",
}


OPTIONAL_SYSTEM_SERVICES = {
    # Printing
    "cups",
    "cups-browsed",

    # AI inference
    "ollama",

    # Bluetooth
    "bluetooth",
    "bluetoothd",

    # mDNS / Bonjour
    "avahi-daemon",
    "avahi",

    # Time synchronisation
    "chrony",
    "chronyd",
    "ntp",
    "ntpd",
    "systemd-timesyncd",   # also listed as critical when it IS the sole NTP

    # Snap daemon
    "snapd",

    # Firmware / modem
    "ModemManager",
    "fwupd",

    # Printer discovery
    "ipp-usb",

    # Audio
    "pipewire",
    "pipewire-pulse",
    "pulseaudio",
    "wireplumber",

    # Location / sensors
    "geoclue",

    # CUPS / IPP
    "colord",
}


USER_APPLICATION_SERVICES = {
    # Databases
    "mysql",
    "mysqld",
    "mariadb",
    "postgresql",
    "mongodb",
    "redis",
    "redis-server",
    "memcached",

    # Web servers
    "nginx",
    "apache2",
    "httpd",

    # Media
    "plex",
    "jellyfin",
    "emby",

    # Mail
    "postfix",
    "dovecot",
    "sendmail",

    # Monitoring
    "prometheus",
    "grafana",
    "grafana-server",
    "node_exporter",
}


DEVELOPMENT_SERVICES = {
    # Containers
    "docker",
    "docker-compose",
    "containerd",
    "podman",

    # VMs
    "libvirtd",
    "virtlogd",
    "qemu",

    # Language servers / build tools
    "jenkins",
    "gitlab-runner",
}


# ============================================================
# CLASSIFICATION FUNCTION
# ============================================================

def classify_service(service_name):
    """
    Return the deterministic tier for a systemd service.

    Parameters
    ----------
    service_name : str
        Service unit name.  The ".service" suffix is stripped before
        matching so callers can pass either form.

    Returns
    -------
    dict with keys:
        tier         : str   — one of the four tiers or "unknown"
        severity     : str   — suggested diagnostic severity
        explanation  : str   — human-readable reason
    """

    if not service_name:
        return _result("unknown", "warning", "Empty service name.")

    # Strip ".service" suffix and surrounding whitespace
    name = service_name.strip()
    if name.endswith(".service"):
        name = name[: -len(".service")]

    # ---------------------------------------------------------
    # Exact match — most specific, checked first
    # ---------------------------------------------------------

    if name in CRITICAL_SYSTEM_SERVICES:
        return _result(
            "critical_system",
            "critical",
            f"{name!r} is a fundamental OS service. "
            "Its failure may impair the system or user sessions.",
        )

    if name in OPTIONAL_SYSTEM_SERVICES:
        return _result(
            "optional_system",
            "warning",
            f"{name!r} provides optional system functionality. "
            "Its failure does not automatically impair core OS operation.",
        )

    if name in USER_APPLICATION_SERVICES:
        return _result(
            "user_application",
            "warning",
            f"{name!r} is a user-installed or third-party application service.",
        )

    if name in DEVELOPMENT_SERVICES:
        return _result(
            "development",
            "info",
            f"{name!r} is a development tooling service.",
        )

    # ---------------------------------------------------------
    # Prefix rules — handles variants like systemd-*, sshd@*, etc.
    # ---------------------------------------------------------

    # All systemd- prefixed services are considered critical
    # (e.g. systemd-journald@0, systemd-udevd-control.socket)
    if name.startswith("systemd-"):
        return _result(
            "critical_system",
            "critical",
            f"{name!r} is a systemd infrastructure service.",
        )

    # User-session systemd instances (@)
    if "@" in name:
        base = name.split("@")[0]

        if base in CRITICAL_SYSTEM_SERVICES:
            return _result(
                "critical_system",
                "critical",
                f"{name!r} is an instance of a critical service.",
            )

        # Snap-based application units
        if base.startswith("snap."):
            return _result(
                "user_application",
                "warning",
                f"{name!r} is a Snap application service.",
            )

    # snap.* units (single-instance form)
    if name.startswith("snap."):
        return _result(
            "user_application",
            "warning",
            f"{name!r} is a Snap application service.",
        )

    # ---------------------------------------------------------
    # Unknown
    # ---------------------------------------------------------

    return _result(
        "unknown",
        "warning",
        f"{name!r} could not be matched to a known service tier. "
        "Treating as potentially significant.",
    )


# ============================================================
# HELPER
# ============================================================

def _result(tier, severity, explanation):
    return {
        "tier": tier,
        "severity": severity,
        "explanation": explanation,
    }


# ============================================================
# FAILED-SERVICE PARSER
# ============================================================

def parse_failed_services(systemctl_output):
    """
    Parse the stdout from:

        systemctl --failed --no-pager --no-legend

    and return a list of unit names.

    Each line looks like:

        ● ollama.service         loaded failed failed Manage Ollama model server
        NetworkManager.service   loaded failed failed Network Manager

    We extract the first token (the unit name), stripping leading
    bullet symbols that systemctl may include.

    Parameters
    ----------
    systemctl_output : str
        Raw stdout from systemctl --failed.

    Returns
    -------
    list[str]
        Unit names, e.g. ["ollama.service", "NetworkManager.service"]
    """

    services = []

    for line in systemctl_output.splitlines():

        line = line.strip()

        if not line:
            continue

        # Strip the Unicode bullet that systemctl sometimes uses
        line = line.lstrip("●•*").strip()

        parts = line.split()

        if not parts:
            continue

        unit = parts[0]

        # Only service units (also accept timer, socket, etc.)
        if "." in unit:
            services.append(unit)

    return services


# ============================================================
# CLI TEST
# ============================================================

if __name__ == "__main__":

    import json

    samples = [
        "NetworkManager.service",
        "ollama.service",
        "systemd-journald.service",
        "cups.service",
        "docker.service",
        "snap.firefox.firefox.service",
        "some-unknown-app.service",
        "bluetooth.service",
    ]

    results = {}

    for s in samples:
        results[s] = classify_service(s)

    print(json.dumps(results, indent=2))
