from ollama_client import ask_qwen


prompt = """
You are NOVA, a Linux diagnostic assistant.

Explain in one short paragraph:

What is the purpose of the Linux kernel?
"""


answer = ask_qwen(prompt)

print("\n===== QWEN RESPONSE =====\n")
print(answer)
