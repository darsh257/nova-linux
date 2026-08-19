from backend.core import collect_system_info
from backend.diagnosis.engine import analyze
from backend.ai.diagnose import diagnose_with_ai


def main():

    print("Collecting Linux telemetry...")

    system_data = collect_system_info()

    print("Running evidence engine...")

    evidence = analyze(system_data)

    print("Sending evidence to Qwen3 8B...")

    result = diagnose_with_ai(evidence)

    print()
    print("=" * 60)
    print("                 NOVA AI DIAGNOSIS")
    print("=" * 60)
    print()

    print(result)


if __name__ == "__main__":
    main()
