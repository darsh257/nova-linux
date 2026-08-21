import json
import os
import subprocess


# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------

SCAN_ROOT = "/"

EXCLUDED_PATHS = {
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/tmp",
    "/snap",
    "/lost+found",
}

TOP_DIRECTORY_LIMIT = 10
TOP_FILE_LIMIT = 20


# ---------------------------------------------------------
# HELPERS
# ---------------------------------------------------------

def is_excluded(path):
    """
    Return True when a path belongs to a filesystem/runtime
    location that should not be recursively scanned.
    """

    normalized = os.path.abspath(path)

    for excluded in EXCLUDED_PATHS:

        if normalized == excluded:
            return True

        if normalized.startswith(excluded + "/"):
            return True

    return False


def get_size(path):
    """
    Return apparent size of a path in bytes.

    Errors are ignored because some Linux system paths may
    disappear or become inaccessible during scanning.
    """

    try:

        result = subprocess.run(
            [
                "du",
                "-sx",
                "--bytes",
                path
            ],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            return 0

        value = result.stdout.strip().split()

        if not value:
            return 0

        return int(value[0])

    except (
        OSError,
        ValueError
    ):
        return 0


def human_size(size):

    units = [
        "B",
        "KB",
        "MB",
        "GB",
        "TB"
    ]

    value = float(size)

    for unit in units:

        if value < 1024:

            return f"{value:.2f} {unit}"

        value /= 1024

    return f"{value:.2f} PB"


# ---------------------------------------------------------
# TOP-LEVEL DIRECTORIES
# ---------------------------------------------------------

def get_top_directories(
    root=SCAN_ROOT,
    limit=TOP_DIRECTORY_LIMIT
):
    """
    Collect immediate directory sizes.

    Uses `du` separately for each accessible directory so that
    permission problems in one directory do not invalidate the
    entire storage scan.
    """

    directories = []

    try:
        entries = os.scandir(root)
    except OSError:
        return directories

    with entries:

        for entry in entries:

            path = entry.path

            if is_excluded(path):
                continue

            try:
                if not entry.is_dir(
                    follow_symlinks=False
                ):
                    continue
            except OSError:
                continue

            try:

                result = subprocess.run(
                    [
                        "du",
                        "-sx",
                        "--bytes",
                        path
                    ],
                    capture_output=True,
                    text=True
                )

                if result.returncode != 0:
                    continue

                parts = result.stdout.strip().split()

                if not parts:
                    continue

                size = int(parts[0])

            except (
                OSError,
                ValueError
            ):
                continue

            directories.append({
                "path": path,
                "size_bytes": size,
                "size_human": human_size(size)
            })

    directories.sort(
        key=lambda item: item["size_bytes"],
        reverse=True
    )

    return directories[:limit]


# ---------------------------------------------------------
# LARGEST FILES
# ---------------------------------------------------------

def get_large_files(
    root=SCAN_ROOT,
    limit=TOP_FILE_LIMIT
):

    files = []

    command = [
        "find",
        root,
        "-xdev",
        "-type",
        "f",
        "-printf",
        "%s\\t%p\\n"
    ]

    try:

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

    except OSError:

        return files

    for line in process.stdout:

        line = line.rstrip()

        if not line:
            continue

        try:

            size_text, path = line.split(
                "\t",
                1
            )

            size = int(size_text)

        except ValueError:

            continue

        if is_excluded(path):
            continue

        files.append({
            "path": path,
            "size_bytes": size,
            "size_human": human_size(size)
        })

    process.wait()

    files.sort(
        key=lambda item: item["size_bytes"],
        reverse=True
    )

    return files[:limit]


# ---------------------------------------------------------
# STORAGE INFORMATION
# ---------------------------------------------------------

def get_storage():

    top_directories = get_top_directories()

    large_files = get_large_files()

    return {
        "scan_root": SCAN_ROOT,

        "top_directories": top_directories,

        "large_files": large_files,

        "policy": {
            "read_only": True,
            "deletion_performed": False,
            "excluded_paths": sorted(
                EXCLUDED_PATHS
            )
        }
    }


# ---------------------------------------------------------
# CLI TEST
# ---------------------------------------------------------

if __name__ == "__main__":

    print(
        json.dumps(
            get_storage(),
            indent=2
        )
    )