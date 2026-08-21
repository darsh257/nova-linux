import os
import time


def _read_loadavg():
    """
    Read /proc/loadavg and return (load1, load5, load15).

    Returns (None, None, None) on any read or parse failure so that
    a missing or unreadable /proc/loadavg never crashes telemetry.
    """

    try:

        with open("/proc/loadavg", "r") as file:

            line = file.readline()

        parts = line.split()

        if len(parts) < 3:
            return None, None, None

        return (
            float(parts[0]),
            float(parts[1]),
            float(parts[2]),
        )

    except (OSError, ValueError):

        return None, None, None


def read_cpu():

    def read():

        with open("/proc/stat", "r") as file:

            line = file.readline()

        values = line.split()[1:]

        values = [int(x) for x in values]

        idle = values[3]

        total = sum(values)

        return total, idle

    total1, idle1 = read()

    time.sleep(0.5)

    total2, idle2 = read()

    total_delta = total2 - total1
    idle_delta = idle2 - idle1

    usage = 0

    if total_delta:
        usage = (
            (total_delta - idle_delta)
            / total_delta
        ) * 100

    load1, load5, load15 = _read_loadavg()

    return {
        "cpu_count": os.cpu_count(),
        "usage_percent": round(usage, 2),
        "load1": load1,
        "load5": load5,
        "load15": load15,
    }


if __name__ == "__main__":

    import json

    print(
        json.dumps(
            read_cpu(),
            indent=2
        )
    )
