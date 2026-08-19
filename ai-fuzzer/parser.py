import json
import sys
from slither.slither import Slither

def parse_contract(sol_file: str) -> dict:
    """
    Принимает путь к .sol файлу.
    Возвращает структурированный словарь с описанием контракта.
    """
    slither = Slither(sol_file)

    result = {}

    # Берём первый контракт из файла
    contract = slither.contracts[0]
    result["contract_name"] = contract.name

    # --- Переменные состояния ---
    result["state_variables"] = [
        var.name for var in contract.state_variables
    ]

    # --- Функции ---
    functions = []
    for fn in contract.functions:
        # Пропускаем служебные функции Solidity
        if fn.name in ["slitherConstructorVariables", "slitherConstructorConstantVariables"]:
            continue
        functions.append({
            "name": fn.name,
            "inputs": [f"{p.type} {p.name}" for p in fn.parameters],
            "visibility": fn.visibility,
            "modifiers": [m.name for m in fn.modifiers]
        })
    result["functions"] = functions

    # --- Инварианты (require и assert внутри функций) ---
    invariants = []
    for fn in contract.functions:
        for node in fn.nodes:
            # Ищем узлы содержащие require() или assert()
            node_str = str(node)
            if "require" in node_str or "assert" in node_str:
                invariants.append({
                    "function": fn.name,
                    "condition": node_str
                })
    result["invariants"] = invariants

    return result


def build_llm_prompt(parsed: dict) -> str:
    """
    Превращает JSON с описанием контракта в системный промпт для LLM.
    """
    functions_text = "\n".join([
        f"  - {fn['name']}({', '.join(fn['inputs'])}) [{fn['visibility']}]"
        for fn in parsed["functions"]
    ])

    invariants_text = "\n".join([
        f"  - в функции {inv['function']}: {inv['condition']}"
        for inv in parsed["invariants"]
    ])

    prompt = f"""Ты эксперт по безопасности смарт-контрактов.

КОНТРАКТ: {parsed["contract_name"]}

ПЕРЕМЕННЫЕ СОСТОЯНИЯ:
{chr(10).join("  - " + v for v in parsed["state_variables"])}

ФУНКЦИИ:
{functions_text}

ИНВАРИАНТЫ (условия которые никогда не должны нарушаться):
{invariants_text}

ЗАДАЧА: сгенерируй цепочку транзакций которая попытается нарушить один из инвариантов.
Ответь СТРОГО в формате JSON, без пояснений, без markdown-блоков.

Формат ответа:
{{
  "scenario_name": "название сценария атаки",
  "target_invariant": "какой инвариант атакуем",
  "transactions": [
    {{"function": "имя функции", "args": [], "sender": "attacker"}},
    ...
  ],
  "expected_violation": "объяснение почему это должно сломать инвариант"
}}"""

    return prompt


if __name__ == "__main__":
    sol_file = sys.argv[1] if len(sys.argv) > 1 else "contracts/SimpleVault.sol"

    print(f"Парсим: {sol_file}\n")
    parsed = parse_contract(sol_file)

    print("=== JSON ===")
    print(json.dumps(parsed, indent=2, ensure_ascii=False))

    print("\n=== ПРОМПТ ДЛЯ LLM ===")
    prompt = build_llm_prompt(parsed)
    print(prompt)

    # Сохраняем JSON и промпт в файлы
    with open("build/contract_parsed.json", "w") as f:
        json.dump(parsed, f, indent=2, ensure_ascii=False)
    with open("build/llm_prompt.txt", "w") as f:
        f.write(prompt)

    print("\n✅ Сохранено: build/contract_parsed.json и build/llm_prompt.txt")
