import json

from backend.ai.ollama_client import ask_qwen
from backend.ai.prompts import build_diagnostic_prompt


def diagnose_with_ai(evidence):

    prompt = build_diagnostic_prompt(
        json.dumps(
            evidence,
            indent=2
        )
    )

    return ask_qwen(prompt)
