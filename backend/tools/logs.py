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


def get_logs():

    errors = run_command(
        [
            "journalctl",
            "-b",
            "-p",
            "err",
            "--no-pager"
        ]
    )

    warnings = run_command(
        [
            "journalctl",
            "-b",
            "-p",
            "warning",
            "--no-pager",
            "-n",
            "50"
        ]
    )

    return {
        "errors": errors,
        "warnings": warnings
    }


if __name__ == "__main__":

    import json

    print(
        json.dumps(
            get_logs(),
            indent=2
        )
    )
