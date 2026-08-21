import requests


OLLAMA_URL = "http://localhost:11434"
MODEL = "qwen3:8b"


def ask_qwen(prompt):

    session = requests.Session()

    session.trust_env = False

    response = session.post(
        f"{OLLAMA_URL}/api/generate",
        json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False
        },
        timeout=180
    )

    response.raise_for_status()

    data = response.json()

    return data["response"]
