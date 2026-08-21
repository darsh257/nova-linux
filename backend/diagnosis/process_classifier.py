"""
NOVA Process Classification

Classifies Linux processes into broad workload categories.

This module is deterministic.
The AI model must not override these classifications.
"""


PROCESS_CATEGORIES = {
    "ai_workload": {
        "llama-server",
        "ollama",
        "ollama_llama_server",
    },

    "browser": {
        "chrome",
        "chromium",
        "chromium-browser",
        "firefox",
        "brave",
        "brave-browser",
        "edge",
        "microsoft-edge",
    },

    "desktop": {
        "gnome-shell",
        "gnome-session",
        "gnome-session-binary",
        "kwin",
        "plasmashell",
        "xfce4-session",
        "xfwm4",
        "cinnamon",
        "mate-panel",
    },

    "development": {
        "python",
        "python3",
        "node",
        "nodejs",
        "npm",
        "yarn",
        "git",
        "code",
        "cursor",
        "antigravity-ide",
        "language_server",
    },

    "kernel": {
        "kworker",
        "ksoftirqd",
        "migration",
        "rcu",
        "watchdog",
    },

    "system_service": {
        "systemd",
        "systemd-journald",
        "systemd-logind",
        "dbus-daemon",
        "NetworkManager",
        "udisksd",
        "avahi-daemon",
        "bluetoothd",
        "cron",
        "cupsd",
    },
}


def classify_process(command):
    """
    Return the deterministic category for a process.

    Parameters
    ----------
    command : str
        Process command/name.

    Returns
    -------
    str
        Process category.
    """

    if not command:
        return "unknown"

    command = command.strip()

    # ---------------------------------------------------------
    # Exact command matching
    # ---------------------------------------------------------

    for category, processes in PROCESS_CATEGORIES.items():

        if command in processes:
            return category

    # ---------------------------------------------------------
    # Kernel worker matching
    # ---------------------------------------------------------

    if command.startswith("kworker/"):
        return "kernel"

    if command.startswith("ksoftirqd/"):
        return "kernel"

    if command.startswith("migration/"):
        return "kernel"

    if command.startswith("cpuhp/"):
        return "kernel"

    # ---------------------------------------------------------
    # Systemd process variants
    # ---------------------------------------------------------

    if command.startswith("systemd"):
        return "system_service"

    # ---------------------------------------------------------
    # Unknown process
    # ---------------------------------------------------------

    return "unknown"


def classify_process_info(process):
    """
    Add classification information to a process dictionary.

    The original process information is preserved.
    """

    result = dict(process)

    category = classify_process(
        process.get("command", "")
    )

    result["classification"] = category

    return result