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


def get_network_info():

    return {
        "interfaces": run_command(
            ["ip", "-brief", "addr"]
        ),

        "routes": run_command(
            ["ip", "route"]
        ),

        "connections": run_command(
            ["ss", "-tuln"]
        )
    }


if __name__ == "__main__":

    import json

    print(
        json.dumps(
            get_network_info(),
            indent=2
        )
    )
