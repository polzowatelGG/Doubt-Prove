from web3 import Web3
from solcx import compile_source, install_solc
import json, requests

# ── константы ────────────────────────────────────────────────────
MAX_ITERATIONS = 5        # максимум попыток LLM
OLLAMA_TIMEOUT = 300      # секунд ожидания ответа
OLLAMA_URL     = "http://localhost:11434/api/generate"
ANVIL_URL      = "http://127.0.0.1:8545"

w3 = Web3(Web3.HTTPProvider(ANVIL_URL))
assert w3.is_connected(), "❌ Anvil не запущен! Запусти anvil в отдельном терминале."

ATTACKER = w3.eth.accounts[0]
VICTIM   = w3.eth.accounts[1]
ACCOUNTS = {"attacker": ATTACKER, "victim": VICTIM}

# ── 1. ПАРСЕР ────────────────────────────────────────────────────
def parse_contract(sol_file: str, contract_name: str) -> dict:
    from slither.slither import Slither
    slither  = Slither(sol_file)
    contract = next(c for c in slither.contracts if c.name == contract_name)

    functions = []
    for fn in contract.functions:
        if fn.name in ["slitherConstructorVariables", "slitherConstructorConstantVariables"]:
            continue
        functions.append({
            "name":       fn.name,
            "inputs":     [f"{p.type} {p.name}" for p in fn.parameters],
            "visibility": fn.visibility,
        })

    invariants = []
    for fn in contract.functions:
        for node in fn.nodes:
            s = str(node)
            if "require" in s or "assert" in s:
                invariants.append({"function": fn.name, "condition": s})

    return {
        "contract_name":   contract.name,
        "state_variables": [v.name for v in contract.state_variables],
        "functions":       functions,
        "invariants":      invariants,
    }


# ── 2. ДЕПЛОЙ ────────────────────────────────────────────────────
def deploy_contract(sol_file: str, contract_name: str):
    install_solc("0.8.0")
    with open(sol_file) as f:
        source = f.read()
    compiled = compile_source(source, output_values=["abi", "bin"], solc_version="0.8.0")
    data     = compiled[f"<stdin>:{contract_name}"]
    Contract = w3.eth.contract(abi=data["abi"], bytecode=data["bin"])
    tx       = Contract.constructor().transact({"from": ATTACKER})
    receipt  = w3.eth.wait_for_transaction_receipt(tx)
    return w3.eth.contract(address=receipt["contractAddress"], abi=data["abi"])


# ── 3. ПРОВЕРКА ИНВАРИАНТОВ ──────────────────────────────────────
def check_invariants(contract) -> list:
    violations      = []
    balance         = contract.functions.balances(ATTACKER).call()
    total           = contract.functions.totalDeposits().call()
    eth_on_contract = w3.eth.get_balance(contract.address)

    if total > eth_on_contract:
        violations.append(
            f"totalDeposits ({total} wei) > ETH на контракте ({eth_on_contract} wei)"
        )
    if balance > total:
        violations.append(
            f"balance аккаунта ({balance} wei) > totalDeposits ({total} wei)"
        )
    return violations


# ── 4. ИСПОЛНЕНИЕ СЦЕНАРИЯ ───────────────────────────────────────
def execute_scenario(contract, transactions: list) -> dict:
    """
    Исполняет список транзакций.
    Возвращает словарь с результатом каждого шага и найденными нарушениями.
    """
    steps      = []
    violations = []

    for tx in transactions:
        fn_name = tx["function"]
        args    = tx.get("args", [])
        sender  = ACCOUNTS.get(tx.get("sender", "attacker"), ATTACKER)
        step    = {"tx": tx, "status": None, "violations": []}

        try:
            fn = getattr(contract.functions, fn_name)
            if fn_name == "deposit":
                value = int(args[0]) if args else 100
                fn().transact({"from": sender, "value": value})
            elif fn_name == "getBalance":
                result = fn().call({"from": sender})
                step["status"] = f"view: {result} wei"
                steps.append(step)
                continue
            else:
                fn(*[int(a) for a in args]).transact({"from": sender})
            step["status"] = "success"
        except Exception as e:
            step["status"] = f"revert: {e}"

        v = check_invariants(contract)
        step["violations"] = v
        violations.extend(v)
        steps.append(step)

    return {"steps": steps, "violations": violations}


# ── 5. LLM — ПЕРВЫЙ ПРОМПТ ───────────────────────────────────────
def build_initial_prompt(parsed: dict) -> str:
    functions_text  = "\n".join(
        f"  - {fn['name']}({', '.join(fn['inputs'])}) [{fn['visibility']}]"
        for fn in parsed["functions"]
    )
    invariants_text = "\n".join(
        f"  - в функции {inv['function']}: {inv['condition']}"
        for inv in parsed["invariants"]
    )
    return f"""Ты эксперт по безопасности смарт-контрактов.

КОНТРАКТ: {parsed["contract_name"]}

ПЕРЕМЕННЫЕ СОСТОЯНИЯ:
{chr(10).join("  - " + v for v in parsed["state_variables"])}

ФУНКЦИИ:
{functions_text}

ИНВАРИАНТЫ (условия которые никогда не должны нарушаться):
{invariants_text}

ЗАДАЧА: сгенерируй цепочку транзакций которая попытается нарушить один из инвариантов.
Ответь СТРОГО в формате JSON без пояснений и без markdown-блоков.

{{
  "scenario_name": "название",
  "target_invariant": "какой инвариант атакуем",
  "transactions": [
    {{"function": "имя", "args": [], "sender": "attacker"}}
  ],
  "expected_violation": "почему это должно сломать инвариант"
}}"""


# ── 6. LLM — ФИДБЕК ПРОМПТ ──────────────────────────────────────
def build_feedback_prompt(parsed: dict, history: list) -> str:
    """
    Формирует промпт с историей всех предыдущих попыток.
    LLM видит что уже пробовали и почему не сработало.
    """
    history_text = ""
    for i, attempt in enumerate(history, 1):
        txs = " → ".join(
            f"{t['function']}({','.join(str(a) for a in t.get('args',[]))})"
            for t in attempt["transactions"]
        )
        result = attempt["result"]
        if result["violations"]:
            outcome = f"НАРУШЕНИЕ НАЙДЕНО: {result['violations']}"
        else:
            reverts = [s for s in result["steps"] if "revert" in str(s.get("status",""))]
            outcome = f"нарушений нет. Ревертов: {len(reverts)}"
        history_text += f"\nПопытка {i}: {txs}\nРезультат: {outcome}\n"

    functions_text = "\n".join(
        f"  - {fn['name']}({', '.join(fn['inputs'])}) [{fn['visibility']}]"
        for fn in parsed["functions"]
    )

    return f"""Ты эксперт по безопасности смарт-контрактов.

КОНТРАКТ: {parsed["contract_name"]}
ФУНКЦИИ:
{functions_text}

ИСТОРИЯ ПРЕДЫДУЩИХ ПОПЫТОК:
{history_text}
Все предыдущие попытки не нашли нарушений инвариантов.
Придумай НОВЫЙ сценарий атаки — другой порядок вызовов, другие суммы, другую логику.
Ответь СТРОГО в формате JSON без пояснений и без markdown-блоков.

{{
  "scenario_name": "название",
  "target_invariant": "какой инвариант атакуем",
  "transactions": [
    {{"function": "имя", "args": [], "sender": "attacker"}}
  ],
  "expected_violation": "почему это должно сработать"
}}"""


# ── 7. ЗАПРОС К LLM ─────────────────────────────────────────────
def ask_llm(prompt: str) -> dict:
    response = requests.post(
        OLLAMA_URL,
        json={"model": "llama3", "prompt": prompt, "stream": False},
        timeout=OLLAMA_TIMEOUT
    )
    raw     = response.json()["response"].strip()
    # убираем markdown-блоки
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    raw = raw.strip()
    # чиним незакрытый JSON
    raw += "}" * (raw.count("{") - raw.count("}"))
    return json.loads(raw)


# ── 8. ГЛАВНЫЙ ЦИКЛ ─────────────────────────────────────────────
def run_fuzzer(sol_file: str, contract_name: str):
    print(f"\n{'='*55}")
    print(f"  AI-FUZZER — {contract_name}")
    print(f"{'='*55}\n")

    # Парсим контракт
    print("📄 Парсим контракт...")
    parsed = parse_contract(sol_file, contract_name)
    print(f"   Найдено функций: {len(parsed['functions'])}, инвариантов: {len(parsed['invariants'])}\n")

    history = []

    for iteration in range(1, MAX_ITERATIONS + 1):
        print(f"{'─'*55}")
        print(f"  Итерация {iteration}/{MAX_ITERATIONS}")
        print(f"{'─'*55}")

        # Генерируем сценарий
        print("🤖 LLM генерирует сценарий атаки...")
        if iteration == 1:
            prompt = build_initial_prompt(parsed)
        else:
            prompt = build_feedback_prompt(parsed, history)

        try:
            scenario = ask_llm(prompt)
        except Exception as e:
            print(f"❌ Ошибка LLM: {e}")
            continue

        print(f"   Сценарий: {scenario.get('scenario_name', '—')}")
        txs_str = " → ".join(
            f"{t['function']}({','.join(str(a) for a in t.get('args',[]))})"
            for t in scenario["transactions"]
        )
        print(f"   Транзакции: {txs_str}")

        # Деплоим свежий контракт для каждой итерации
        contract = deploy_contract(sol_file, contract_name)

        # Исполняем сценарий
        print("⚡ Исполняем на Anvil...")
        result = execute_scenario(contract, scenario["transactions"])

        # Сохраняем в историю
        history.append({"transactions": scenario["transactions"], "result": result})

        # Проверяем результат
        if result["violations"]:
            print(f"\n🚨 БАГ НАЙДЕН на итерации {iteration}!")
            for v in result["violations"]:
                print(f"   {v}")
            print(f"\n   Сценарий: {scenario.get('scenario_name')}")
            print(f"   Транзакции: {txs_str}")

            # Сохраняем финальный отчёт
            report = {
                "contract": contract_name,
                "found_on_iteration": iteration,
                "scenario": scenario,
                "violations": result["violations"],
            }
            with open("build/fuzzer_report.json", "w") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            print(f"\n✅ Отчёт сохранён: build/fuzzer_report.json")
            return report

        else:
            reverts = sum(1 for s in result["steps"] if "revert" in str(s.get("status","")))
            print(f"   Нарушений нет (ревертов: {reverts}). Передаём фидбек в LLM...")

    print(f"\n⚠️  За {MAX_ITERATIONS} итераций баг не найден.")
    print("   Попробуй увеличить MAX_ITERATIONS или сменить модель.")
    return None


# ── ЗАПУСК ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    sol_file      = sys.argv[1] if len(sys.argv) > 1 else "contracts/BuggyVault.sol"
    contract_name = sys.argv[2] if len(sys.argv) > 2 else "BuggyVault"
    run_fuzzer(sol_file, contract_name)
