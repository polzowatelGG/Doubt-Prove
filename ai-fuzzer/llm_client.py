import requests
import json

def ask_llm(prompt: str) -> str:
    response = requests.post(
        "http://localhost:11434/api/generate",
        json={
            "model": "llama3",
            "prompt": prompt,
            "stream": False
        },
        timeout=300
    )
    return response.json()["response"]


def parse_llm_response(raw: str) -> dict:
    cleaned = raw.strip()
    # Убираем markdown-блоки если модель их добавила
    if cleaned.startswith("```"):
        cleaned = cleaned.split("```")[1]
        if cleaned.startswith("json"):
            cleaned = cleaned[4:]
    cleaned = cleaned.strip()
    # Чиним незакрытый JSON — добавляем } если не хватает
    open_braces = cleaned.count("{")
    close_braces = cleaned.count("}")
    if open_braces > close_braces:
        cleaned += "}" * (open_braces - close_braces)
    return json.loads(cleaned)


if __name__ == "__main__":
    with open("build/llm_prompt.txt") as f:
        prompt = f.read()

    print("Отправляем промпт в LLM...")
    print("(может занять до 5 минут)\n")

    raw_response = ask_llm(prompt)

    print("=== RAW ОТВЕТ LLM ===")
    print(raw_response)

    print("\n=== ПАРСИМ JSON ===")
    try:
        scenario = parse_llm_response(raw_response)
        print(json.dumps(scenario, indent=2, ensure_ascii=False))
        with open("build/attack_scenario.json", "w") as f:
            json.dump(scenario, f, indent=2, ensure_ascii=False)
        print("\n✅ Сценарий атаки сохранён: build/attack_scenario.json")
    except json.JSONDecodeError as e:
        print(f"❌ LLM вернула не валидный JSON: {e}")
        print("Сырой ответ сохранён выше")
