import os
import time


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

    return {
        "cpu_count": os.cpu_count(),
        "usage_percent": round(usage, 2)
    }


if __name__ == "__main__":

    import json

    print(
        json.dumps(
            read_cpu(),
            indent=2
        )
    )
