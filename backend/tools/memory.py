import json


def read_meminfo():

    raw = {}

    with open("/proc/meminfo", "r") as file:

        for line in file:

            key, value = line.split(":", 1)

            value = value.strip()

            number = int(value.split()[0])

            raw[key] = number

    return raw


def get_memory():

    mem = read_meminfo()

    total = mem["MemTotal"]
    available = mem["MemAvailable"]

    swap_total = mem["SwapTotal"]
    swap_free = mem["SwapFree"]

    memory_used = total - available
    swap_used = swap_total - swap_free

    return {
        "memory": {
            "total_mb": round(total / 1024, 2),
            "used_mb": round(memory_used / 1024, 2),
            "available_mb": round(available / 1024, 2),
            "usage_percent": round(
                (memory_used / total) * 100,
                2
            )
        },

        "swap": {
            "total_mb": round(swap_total / 1024, 2),
            "used_mb": round(swap_used / 1024, 2),
            "usage_percent": (
                round((swap_used / swap_total) * 100, 2)
                if swap_total
                else 0
            )
        }
    }


if __name__ == "__main__":

    print(
        json.dumps(
            get_memory(),
            indent=2
        )
    )
