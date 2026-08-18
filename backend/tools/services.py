import subprocess


def run_command(command):

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False
    )

    return {
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
        "return_code": result.returncode
    }


def get_services():

    failed = run_command(
        [
            "systemctl",
            "--failed",
            "--no-pager",
            "--no-legend"
        ]
    )

    running = run_command(
        [
            "systemctl",
            "list-units",
            "--type=service",
            "--state=running",
            "--no-pager",
            "--no-legend"
        ]
    )

    return {
        "failed_services": failed,
        "running_services": running
    }


if __name__ == "__main__":

    import json

    print(
        json.dumps(
            get_services(),
            indent=2
        )
    )
