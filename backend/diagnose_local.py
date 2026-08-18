import json

from core import collect_system_info
from diagnosis.engine import analyze


def main():

    print("Collecting Linux telemetry...")

    data = collect_system_info()

    print("Running diagnostic rules...")

    result = analyze(data)

    print("\n==============================")
    print("       NOVA EVIDENCE")
    print("==============================\n")

    print(
        json.dumps(
            result,
            indent=2
        )
    )


if __name__ == "__main__":
    main()
