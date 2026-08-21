import subprocess


def run_ps(sort_by, limit):
    command = [
        "ps",
        "-eo",
        "pid,ppid,user,%cpu,%mem,rss,stat,etime,comm",
        f"--sort={sort_by}"
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True
    )

    lines = result.stdout.strip().splitlines()

    processes = []

    for line in lines[1:limit + 1]:

        parts = line.split(None, 8)

        if len(parts) < 9:
            continue

        (
            pid,
            ppid,
            user,
            cpu,
            memory,
            rss,
            state,
            elapsed,
            command
        ) = parts

        processes.append({
            "pid": int(pid),
            "ppid": int(ppid),
            "user": user,
            "cpu_percent": float(cpu),
            "memory_percent": float(memory),
            "rss_kb": int(rss),
            "state": state,
            "elapsed": elapsed,
            "command": command
        })

    return processes


def get_processes(limit=10):

    return {
        "top_cpu": run_ps("-%cpu", limit),
        "top_memory": run_ps("-%mem", limit)
    }


if __name__ == "__main__":

    import json

    print(
        json.dumps(
            get_processes(),
            indent=2
        )
    )