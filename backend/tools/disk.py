import json
import subprocess


def get_disk():

    output = subprocess.check_output(
        ["df", "-P", "/"],
        text=True
    )

    lines = output.strip().splitlines()

    values = lines[1].split()

    filesystem = values[0]
    total = values[1]
    used = values[2]
    available = values[3]
    usage = values[4]

    return {
        "filesystem": filesystem,
        "total_kb": int(total),
        "used_kb": int(used),
        "available_kb": int(available),
        "usage_percent": int(
            usage.replace("%", "")
        )
    }


if __name__ == "__main__":

    print(
        json.dumps(
            get_disk(),
            indent=2
        )
    )
