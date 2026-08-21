import os


# ---------------------------------------------------------
# STORAGE CLASSIFICATION
# ---------------------------------------------------------

def classify_storage_path(path):
    """
    Classify a filesystem object.

    Classification is informational only.
    It does NOT imply that the object should be deleted.
    """

    normalized = path.lower()

    # -----------------------------------------
    # SWAP
    # -----------------------------------------

    if (
        normalized == "/swap.img"
        or normalized.endswith("/swapfile")
    ):
        return "swap"

    # -----------------------------------------
    # ARCHIVES / DISK IMAGES
    # -----------------------------------------

    archive_extensions = (
        ".tar",
        ".tar.gz",
        ".tgz",
        ".zip",
        ".7z",
        ".rar",
        ".iso",
        ".img",
    )

    if normalized.endswith(archive_extensions):
        return "archive"

    # -----------------------------------------
    # AI MODEL DATA
    # -----------------------------------------

    if (
        "/.ollama/models/" in normalized
        or "/ollama/models/" in normalized
        or "/huggingface/" in normalized
        or "/transformers/" in normalized
        or "/gguf/" in normalized
    ):
        return "ai_model"

    # -----------------------------------------
    # AI RUNTIME / LIBRARIES
    # -----------------------------------------

    if (
        "/ollama/" in normalized
        or "/llama.cpp/" in normalized
        or "libggml" in normalized
        or "libcublas" in normalized
        or "libcuda" in normalized
    ):
        return "ai_runtime"

    # -----------------------------------------
    # SNAP PACKAGES
    # -----------------------------------------

    if (
        "/var/lib/snapd/snaps/" in normalized
        or "/var/lib/snapd/seed/snaps/" in normalized
        or normalized.endswith(".snap")
    ):
        return "package_snap"

    # -----------------------------------------
    # KERNEL / BOOT INFRASTRUCTURE
    # -----------------------------------------

    if (
        normalized.startswith("/boot/")
        or "/kdump/" in normalized
        or normalized.endswith("vmlinuz")
        or normalized.endswith(".img")
        or normalized.endswith(".efi")
    ):
        return "kernel_boot"

    # -----------------------------------------
    # SYSTEM FILES
    # -----------------------------------------

    if (
        normalized.startswith("/usr/")
        or normalized.startswith("/lib/")
        or normalized.startswith("/lib64/")
        or normalized.startswith("/bin/")
        or normalized.startswith("/sbin/")
        or normalized.startswith("/etc/")
    ):
        return "system_file"

    # -----------------------------------------
    # APPLICATION FILES
    # -----------------------------------------

    application_paths = (
        "/opt/",
        "/usr/local/",
        "/var/lib/",
        "/var/cache/",
    )

    if normalized.startswith(application_paths):
        return "application_data"

    # -----------------------------------------
    # USER DATA
    # -----------------------------------------

    if normalized.startswith("/home/"):
        return "user_data"

    # -----------------------------------------
    # UNKNOWN
    # -----------------------------------------

    return "unknown"

# ---------------------------------------------------------
# HUMAN READABLE EXPLANATION
# ---------------------------------------------------------

def explain_storage_classification(classification):

    explanations = {

        "ai_model":
            "AI model data. Large size may be intentional "
            "when local AI models are installed.",

        "ai_runtime":
            "AI runtime or acceleration library. This may "
            "be required by local AI inference software.",

        "swap":
            "Swap storage. This is system-managed virtual "
            "memory and should not be treated as ordinary "
            "user data.",

        "package_snap":
            "Snap package data. Multiple versions may exist "
            "because Snap maintains package revisions.",

        "kernel_boot":
            "Kernel or boot infrastructure. Do not recommend "
            "deletion without verifying installed kernel and "
            "boot dependencies.",

        "system_file":
            "System file. Do not recommend deletion without "
            "specific evidence that it is unnecessary.",

        "application_data":
            "Application data or installed software. "
            "Large size does not by itself indicate a problem.",

        "user_data":
            "User-owned data. Requires user context before "
            "recommending removal.",

        "archive":
            "Archive or disk image. It may be intentionally "
            "stored by the user.",

        "unknown":
            "Storage object with no reliable classification."
    }

    return explanations.get(
        classification,
        "Unknown storage object."
    )

# ---------------------------------------------------------
# ANALYZE LARGE FILES
# ---------------------------------------------------------

def analyze_large_files(
    large_files,
    large_file_threshold_bytes=1_000_000_000
):
    """
    Analyze large files without making deletion decisions.

    Default threshold:
        1 GB

    Returns informational observations.
    """

    observations = []

    for item in large_files:

        path = item.get("path")
        size_bytes = item.get("size_bytes", 0)
        size_human = item.get(
            "size_human",
            "unknown"
        )

        if not path:
            continue

        classification = classify_storage_path(
            path
        )

        observation = {
            "path": path,
            "size_bytes": size_bytes,
            "size_human": size_human,
            "classification": classification,
            "explanation":
                explain_storage_classification(
                    classification
                ),
            "large": (
                size_bytes >=
                large_file_threshold_bytes
            ),
            "deletion_recommended": False
        }

        observations.append(
            observation
        )

    return observations


# ---------------------------------------------------------
# ANALYZE TOP DIRECTORIES
# ---------------------------------------------------------

def analyze_directories(
    directories
):
    """
    Classify top-level directories.

    Directory size alone is not treated as an anomaly.
    """

    observations = []

    for item in directories:

        path = item.get("path")
        size_bytes = item.get(
            "size_bytes",
            0
        )

        if not path:
            continue

        observations.append({
            "path": path,
            "size_bytes": size_bytes,
            "size_human": item.get(
                "size_human",
                "unknown"
            ),
            "classification":
                classify_storage_path(path),
            "deletion_recommended": False
        })

    return observations


# ---------------------------------------------------------
# MAIN STORAGE INTELLIGENCE
# ---------------------------------------------------------

def analyze_storage(
    storage
):
    """
    Convert raw storage telemetry into structured
    storage intelligence.

    This layer is READ-ONLY.

    It does not:
        - delete files
        - modify files
        - mount filesystems
        - change permissions
        - execute cleanup commands
    """

    if not storage:
        return {
            "large_files": [],
            "directories": [],
            "policy": {
                "read_only": True,
                "deletion_recommended": False
            }
        }

    large_files = storage.get(
        "large_files",
        []
    )

    directories = storage.get(
        "top_directories",
        []
    )

    analyzed_files = analyze_large_files(
        large_files
    )

    analyzed_directories = analyze_directories(
        directories
    )

    return {
        "large_files": analyzed_files,

        "directories":
            analyzed_directories,

        "policy": {
            "read_only": True,
            "deletion_recommended": False,
            "automatic_cleanup": False
        }
    }


# ---------------------------------------------------------
# TEST
# ---------------------------------------------------------

if __name__ == "__main__":

    import json

    from backend.tools.storage import (
        get_storage
    )

    storage = get_storage()

    result = analyze_storage(
        storage
    )

    print(
        json.dumps(
            result,
            indent=2
        )
    )