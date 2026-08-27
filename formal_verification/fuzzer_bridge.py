"""
fuzzer_bridge.py — Фаза 6: фаззер для SimpleBridge.sol

СХЕМА РАБОТЫ (обновлено):
  Этап 1 "blind"  — LLM получает автоматически извлечённое (через Slither)
                     описание контракта БЕЗ рецепта атаки и пытается найти
                     баг сама.
  Этап 2 "guided" — запускается ТОЛЬКО если Этап 1 не нашёл баг за
                     отведённые итерации. Контракт деплоится и история
                     попыток начинается ЗАНОВО (с нуля), но в промпт
                     добавляется BRIDGE_CONTEXT — ручное описание с
                     подсказкой порядка действий (deposit -> setAttackParams
                     -> withdraw).
  Итог — три возможных исхода одного прогона:
    stage="blind"      — баг найден САМОСТОЯТЕЛЬНО, без подсказки
    stage="guided"      — баг найден ТОЛЬКО после подсказки
    stage="not_found"  — баг не найден даже с подсказкой

Почему история попыток обнуляется между этапами: если тащить в guided-этап
неудачные blind-попытки, промпт guided-этапа станет "грязным" и его нельзя
будет честно сравнить с результатом отдельного независимого guided-прогона.
Обнуление истории гарантирует, что guided-этап статистически эквивалентен
самостоятельному guided-прогону "с нуля".

Запуск:
    source venv/bin/activate
    python fuzzer_bridge.py
"""

from web3 import Web3
from solcx import compile_source, install_solc
import json, requests, secrets, re

MAX_ITERATIONS_BLIND  = 8   # бюджет итераций для этапа "без подсказки"
MAX_ITERATIONS_GUIDED = 8   # бюджет итераций для этапа "с подсказкой"
OLLAMA_TIMEOUT = 300
OLLAMA_URL     = "http://localhost:11434/api/generate"
ANVIL_URL      = "http://127.0.0.1:8545"
SOLC_VERSION   = "0.8.0"
SOL_FILE       = "contracts/SimpleBridge.sol"

w3 = Web3(Web3.HTTPProvider(ANVIL_URL))
assert w3.is_connected(), "❌ Anvil не запущен!"

ATTACKER = w3.eth.accounts[0]
VICTIM   = w3.eth.accounts[1]
ACCOUNTS = {"attacker": ATTACKER, "victim": VICTIM}


# ---------------------------------------------------------------------------
# 1. Компиляция и деплой обоих контрактов (без изменений)
# ---------------------------------------------------------------------------

def compile_all(sol_file):
    install_solc(SOLC_VERSION)
    with open(sol_file) as f:
        source = f.read()
    compiled = compile_source(source, output_values=["abi", "bin"], solc_version=SOLC_VERSION)
    return compiled


def deploy_bridge_and_attacker(sol_file):
    """
    Деплоит SimpleBridge (attacker сразу как валидатор), MaliciousReceiver,
    привязанный к адресу моста, и регистрирует attacker_contract как
    валидатора — это нужно, чтобы реентрантный вызов withdraw() прошёл
    проверку require(validators[msg.sender]).
    Возвращает (bridge_contract, attacker_contract).
    """
    compiled = compile_all(sol_file)
    bridge_data   = compiled[f"<stdin>:SimpleBridge"]
    attacker_data = compiled[f"<stdin>:MaliciousReceiver"]

    Bridge = w3.eth.contract(abi=bridge_data["abi"], bytecode=bridge_data["bin"])
    tx = Bridge.constructor([ATTACKER]).transact({"from": ATTACKER})
    receipt = w3.eth.wait_for_transaction_receipt(tx)
    bridge = w3.eth.contract(address=receipt["contractAddress"], abi=bridge_data["abi"])

    Attacker = w3.eth.contract(abi=attacker_data["abi"], bytecode=attacker_data["bin"])
    tx2 = Attacker.constructor(bridge.address).transact({"from": ATTACKER})
    receipt2 = w3.eth.wait_for_transaction_receipt(tx2)
    attacker_contract = w3.eth.contract(address=receipt2["contractAddress"], abi=attacker_data["abi"])

    tx3 = bridge.functions.addValidator(attacker_contract.address).transact({"from": ATTACKER})
    w3.eth.wait_for_transaction_receipt(tx3)

    return bridge, attacker_contract


# ---------------------------------------------------------------------------
# 2. Инварианты моста (без изменений)
# ---------------------------------------------------------------------------

def check_invariants(bridge):
    violations = []
    current_block  = w3.eth.block_number
    total_locked   = bridge.functions.totalLocked().call(block_identifier=current_block)
    total_minted   = bridge.functions.totalMinted().call(block_identifier=current_block)
    eth_on_bridge  = w3.eth.get_balance(bridge.address, block_identifier=current_block)

    if total_locked > eth_on_bridge:
        violations.append(
            f"INV-1 нарушен: totalLocked ({total_locked} wei) > "
            f"реальный ETH на мосту ({eth_on_bridge} wei) — мост опустошён сверх учёта"
        )

    if total_locked != total_minted:
        violations.append(
            f"INV-2 нарушен: totalLocked ({total_locked}) != totalMinted ({total_minted})"
        )

    withdrawals = bridge.events.Withdrawn.get_logs(from_block=0)
    message_counts = {}
    for w in withdrawals:
        mid = w["args"]["messageId"]
        mid = mid.hex() if hasattr(mid, "hex") else str(mid)
        message_counts[mid] = message_counts.get(mid, 0) + 1
    for mid, count in message_counts.items():
        if count > 1:
            violations.append(
                f"INV-3 нарушен: messageId {mid} был успешно выведен {count} раз(а) "
                f"вместо 1 — double-spend через reentrancy в withdraw()"
            )

    return violations


# ---------------------------------------------------------------------------
# 3. Исполнение сценария (без изменений)
# ---------------------------------------------------------------------------

def new_message_id():
    return "0x" + secrets.token_hex(32)


def execute_scenario(bridge, attacker_contract, transactions):
    steps, violations = [], []
    message_ids = {}

    for tx in transactions:
        fn_name = tx["function"]
        # Модель иногда пишет "SimpleBridge.deposit" вместо "deposit" —
        # берём только последнюю часть после точки, если она есть.
        fn_name = fn_name.split(".")[-1]
        # tx.get("args", []) подставляет [] только если ключ ОТСУТСТВУЕТ.
        # Модель иногда явно пишет "args": null (валидный JSON!) — тогда
        # get() вернёт None, а не наш default, и дальнейшая итерация по
        # args упадёт с 'NoneType' object is not iterable. Ловим и это.
        args = tx.get("args") or []
        sender  = ACCOUNTS.get(tx.get("sender", "attacker"), ATTACKER)
        step    = {"tx": tx, "status": None, "violations": []}

        try:
            if fn_name == "receive":
                # receive() нельзя вызвать напрямую — это спец-функция
                # Solidity, срабатывающая автоматически при получении ETH
                # (например, внутри withdraw() когда мост шлёт средства
                # attacker_contract). Явный вызов игнорируем как no-op,
                # не считаем это revert-ом, чтобы не сбивать модель с толку —
                # но и не выполняем ничего.
                step["status"] = "skipped: receive() вызывается автоматически, не напрямую"

            elif fn_name == "deposit":
                # Раньше брали строго args[0] — если модель прислала
                # ["", "1000000000000000000"] (пустая строка первым
                # аргументом), это падало с сырым Python-исключением
                # вместо честного revert-а. Теперь, как и для withdraw/
                # setAttackParams, ищем ПЕРВОЕ значение, которое реально
                # парсится как число, и игнорируем пустые/нечисловые.
                value = 1000
                for a in args:
                    try:
                        value = int(a)
                        break
                    except (ValueError, TypeError):
                        continue
                bridge_tx = bridge.functions.deposit().transact({"from": sender, "value": value})
                w3.eth.wait_for_transaction_receipt(bridge_tx)
                step["status"] = "success"

            elif fn_name == "withdraw":
                to_alias  = args[0] if len(args) > 0 else "attacker_contract"
                amount    = 500
                msg_alias = "m1"
                for a in args[1:]:
                    try:
                        amount = int(a)
                    except (ValueError, TypeError):
                        msg_alias = str(a)

                to_addr = attacker_contract.address if to_alias == "attacker_contract" else ACCOUNTS.get(to_alias, ATTACKER)

                if msg_alias not in message_ids:
                    message_ids[msg_alias] = new_message_id()
                message_id = message_ids[msg_alias]

                bridge_tx = bridge.functions.withdraw(to_addr, amount, message_id).transact({"from": sender})
                w3.eth.wait_for_transaction_receipt(bridge_tx)
                step["status"] = "success"

            elif fn_name == "setAttackParams":
                msg_alias     = "m1"
                numeric_args  = []
                for a in args:
                    try:
                        numeric_args.append(int(a))
                    except (ValueError, TypeError):
                        msg_alias = str(a)
                amount        = numeric_args[0] if len(numeric_args) > 0 else 500
                max_reentries = numeric_args[1] if len(numeric_args) > 1 else 3

                if msg_alias not in message_ids:
                    message_ids[msg_alias] = new_message_id()
                message_id = message_ids[msg_alias]

                bridge_tx = attacker_contract.functions.setAttackParams(message_id, amount, max_reentries).transact({"from": sender})
                w3.eth.wait_for_transaction_receipt(bridge_tx)
                step["status"] = "success"

            elif fn_name == "addValidator":
                addr = ACCOUNTS.get(args[0], ATTACKER) if args else ATTACKER
                bridge_tx = bridge.functions.addValidator(addr).transact({"from": sender})
                w3.eth.wait_for_transaction_receipt(bridge_tx)
                step["status"] = "success"

            else:
                step["status"] = f"revert: неизвестная функция {fn_name}"

        except Exception as e:
            step["status"] = f"revert: {e}"

        v = check_invariants(bridge)
        step["violations"] = v
        violations.extend(v)
        steps.append(step)

    violations = list(dict.fromkeys(violations))
    return {"steps": steps, "violations": violations}


# ---------------------------------------------------------------------------
# 4. Парсинг контракта через Slither — "честная" версия без подсказок
# ---------------------------------------------------------------------------

def parse_contract_by_name(sol_file: str, contract_name: str) -> dict:
    """
    Автоматически извлекает функции и переменные состояния контракта
    по имени через Slither. Аналог parse_contract() из parser.py/fuzzer.py,
    но умеет брать нужный контракт из файла, где их несколько
    (SimpleBridge.sol содержит SimpleBridge И MaliciousReceiver).
    """
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

    return {
        "contract_name":   contract.name,
        "state_variables": [v.name for v in contract.state_variables],
        "functions":       functions,
    }


def build_bridge_context_blind(sol_file: str) -> str:
    """
    Контекст БЕЗ рецепта атаки. Функции берутся автоматически через
    Slither. LLM видит структуру контракта и список инвариантов
    (инварианты — это законная постановка задачи, а не подсказка решения,
    так же как echidna_*() функции в классическом фаззинге), но НЕ видит
    рекомендованный порядок вызовов.
    """
    bridge_info   = parse_contract_by_name(sol_file, "SimpleBridge")
    attacker_info = parse_contract_by_name(sol_file, "MaliciousReceiver")

    def fmt_functions(info):
        return "\n".join(
            f"  - {fn['name']}({', '.join(fn['inputs'])}) [{fn['visibility']}]"
            for fn in info["functions"]
        )

    return f"""
КОНТРАКТ 1: {bridge_info['contract_name']} (L1-сторона моста)
Переменные состояния: {', '.join(bridge_info['state_variables'])}
Функции:
{fmt_functions(bridge_info)}

КОНТРАКТ 2: {attacker_info['contract_name']} (вспомогательный контракт,
уже задеплоен и доступен под алиасом "attacker_contract" в поле "to_alias"
и "sender". Он умеет получать ETH через receive() и в своей внутренней
логике может повторно вызывать функции моста при получении ETH.)
Переменные состояния: {', '.join(attacker_info['state_variables'])}
Функции:
{fmt_functions(attacker_info)}

КОНТЕКСТ: attacker и attacker_contract уже являются валидаторами моста
с самого начала сценария.

ИНВАРИАНТЫ (то что нужно нарушить):
  - INV-1: totalLocked не может превышать реальный ETH-баланс контракта
  - INV-2: totalLocked должен быть равен totalMinted
  - INV-3: ни один messageId не должен быть успешно выведен (withdraw) больше одного раза
"""


# BRIDGE_CONTEXT — версия С подсказкой (этап "guided"). Используется,
# только если этап "blind" не нашёл баг сам.
BRIDGE_CONTEXT = """
КОНТРАКТ: SimpleBridge (L1-сторона моста)
ФУНКЦИИ:
  - deposit() payable — блокирует ETH отправителя на мосту
  - withdraw(to_alias, amount, message_alias) — валидатор выводит средства получателю.
      to_alias: "attacker_contract" (реентранси-контракт) или "attacker"/"victim" (обычный адрес)
      message_alias: любая строка-метка, например "m1" — если использовать
      ОДИНАКОВЫЙ message_alias дважды, это будет ПОПЫТКА REPLAY того же messageId
  - setAttackParams(message_alias, amount, max_reentries) — настраивает
      attacker_contract на реентрантный повторный вызов withdraw() из своего
      receive(), когда он получит ETH. max_reentries — сколько раз он попробует
      повторно вызвать withdraw с теми же message_alias и amount.
  - addValidator(who) — только owner может добавить валидатора (attacker уже валидатор)

ВАЖНО: attacker и attacker_contract уже являются валидаторами с начала
сценария, addValidator вызывать не нужно.
Чтобы атака состоялась, порядок обычно такой:
  1. deposit — залить ETH в мост (например от attacker)
  2. setAttackParams — настроить attacker_contract на реентранси с тем же message_alias
  3. withdraw с to_alias="attacker_contract" и тем же message_alias, amount

ИНВАРИАНТЫ (то что нужно нарушить):
  - INV-1: totalLocked не может превышать реальный ETH-баланс контракта
  - INV-2: totalLocked должен быть равен totalMinted
  - INV-3: ни один messageId не должен быть успешно выведен (withdraw) больше одного раза
"""


# ---------------------------------------------------------------------------
# 5. Промпты — параметризованы режимом mode="blind" | "guided"
# ---------------------------------------------------------------------------

def get_context(mode: str) -> str:
    if mode == "guided":
        return BRIDGE_CONTEXT
    return build_bridge_context_blind(SOL_FILE)


# Формат аргументов в "args" — это описание ИНТЕРФЕЙСА ответа (как наш
# исполнитель transactions разбирает JSON), а не подсказка решения.
# Нужен ОДИНАКОВО в обоих режимах, иначе модель, увидев реальные типы
# Solidity (address, bytes32) из Slither, начинает присылать
# "голые" адреса/hex без кавычек — это ломает JSON-парсинг и не
# относится к тому, нашла модель баг или нет.
ARGS_FORMAT_NOTE = """
ФОРМАТ "args" (обязательно соблюдать, иначе транзакция не выполнится):
  - ВСЕ значения в "args" — строки в кавычках, даже числа: "90", а не 90.
  - Адреса указывай алиасами, а НЕ настоящими 0x-адресами:
    "attacker", "victim" или "attacker_contract".
  - messageId указывай произвольной строкой-меткой, например "m1", "m2" —
    одинаковая метка в двух разных транзакциях означает ОДИН И ТОТ ЖЕ
    messageId (используется для проверки replay/double-spend).
  - НИКОГДА не используй Solidity-нотацию единиц измерения: "1 ether",
    "500 wei", "2 gwei" и т.п. — это не валидный JSON. Указывай суммы
    ТОЛЬКО как обычное число в wei, в кавычках: "1000000000000000000"
    (это и есть 1 ether в wei), а не "1 ether".
  Пример корректной транзакции:
    {"function":"withdraw","args":["attacker_contract","90","m1"],"sender":"attacker"}
  - "function" — только имя функции БЕЗ префикса контракта
    (пиши "withdraw", а НЕ "SimpleBridge.withdraw").
  - "receive" вызывать напрямую нельзя — это специальная функция
    Solidity, она срабатывает САМА при получении ETH контрактом
    (например, когда withdraw() отправляет средства attacker_contract).
    Не добавляй её в transactions как отдельный шаг.
  - deposit ТОЖЕ принимает сумму первым элементом args (сколько ETH
    внести), например {"function":"deposit","args":["1000000000000"],...} —
    без суммы будет внесена дефолтная маленькая сумма, и последующий
    withdraw на большую сумму гарантированно упадёт с "insufficient
    bridge liquidity" вне зависимости от того, правильная атака или нет.
"""


def build_initial_prompt(mode: str) -> str:
    context = get_context(mode)
    return f"""Ты эксперт по безопасности смарт-контрактов, специализируешься на мостах L1-L2.
{context}
{ARGS_FORMAT_NOTE}
ЗАДАЧА: сгенерируй цепочку транзакций которая нарушит один из инвариантов.
Ответь СТРОГО в JSON без markdown, без пояснений:
{{"scenario_name":"...","target_invariant":"INV-1, INV-2 или INV-3","transactions":[{{"function":"...","args":[],"sender":"attacker"}}],"expected_violation":"..."}}"""


def build_feedback_prompt(history, mode: str) -> str:
    context = get_context(mode)
    history_text = ""
    for i, attempt in enumerate(history, 1):
        txs = " → ".join(
            f"{t['function']}({','.join(str(a) for a in t.get('args', []))})"
            for t in attempt["transactions"]
        )
        outcome = f"НАРУШЕНИЕ: {attempt['result']['violations']}" if attempt["result"]["violations"] else "нарушений нет"
        history_text += f"\nПопытка {i}: {txs}\nРезультат: {outcome}\n"
    return f"""Ты эксперт по безопасности смарт-контрактов.
{context}
{ARGS_FORMAT_NOTE}
ИСТОРИЯ ПОПЫТОК:\n{history_text}
Придумай НОВЫЙ сценарий — проверь другой порядок вызовов, другие суммы, другую логику.
Ответь СТРОГО в JSON без markdown:
{{"scenario_name":"...","target_invariant":"INV-1, INV-2 или INV-3","transactions":[{{"function":"...","args":[],"sender":"attacker"}}],"expected_violation":"..."}}"""


def sanitize_llm_json(raw: str) -> str:
    """
    Механическая починка типичных невалидных для JSON конструкций,
    которые LLM вставляет несмотря на явную инструкцию в промпте
    (модель стохастична — на промпт нельзя полагаться на 100%).
    Это защитный слой ПОВЕРХ инструкций в промпте, а не замена им.

    Правит:
      - Solidity-нотацию единиц: "1 ether" -> число в wei, "500 wei" -> "500"
      - "голые" (без кавычек) идентификаторы и hex-литералы как элементы
        массива args: [attacker_contract, 0x001] -> ["attacker_contract", "0x001"]
    """
    UNITS = {"ether": 10**18, "gwei": 10**9, "wei": 1}

    def repl_unit(m):
        num, unit = m.group(1), m.group(2)
        return str(int(float(num) * UNITS[unit]))

    raw = re.sub(r'(\d+(?:\.\d+)?)\s*(ether|gwei|wei)\b', repl_unit, raw)

    def quote_bare(m):
        prefix, token, suffix = m.group(1), m.group(2), m.group(3)
        if token in ("true", "false", "null") or re.fullmatch(r'-?\d+(\.\d+)?', token):
            return f"{prefix}{token}{suffix}"
        return f'{prefix}"{token}"{suffix}'

    raw = re.sub(
        r'(?<=[\[,])(\s*)([A-Za-z_][A-Za-z0-9_]*|0x[0-9a-fA-F]+)(\s*)(?=[,\]])',
        quote_bare,
        raw,
    )
    return raw


def try_parse_scenario(raw: str) -> dict:
    """
    Несколько стратегий разбора ответа модели, от простой к защитной.
    Стратегия 1 — как есть. Стратегия 2 — на случай, если модель потеряла
    внешнюю обёртку {"scenario_name":..., "transactions":[...]} и прислала
    просто список транзакций через запятую без [] снаружи — оборачиваем
    сами и восстанавливаем недостающие поля-заглушки.

    ВАЖНО (нашли на 30-прогонной серии): нельзя сохранить объект
    исключения из "except ... as e:" для использования ПОСЛЕ блока —
    Python автоматически удаляет такую переменную сразу по выходу из
    except (чтобы не было циклических ссылок на traceback). Поэтому
    ошибку сохраняем не как сам объект исключения, а как обычную
    переменную, объявленную ДО try/except.
    """
    error_to_raise = None

    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        error_to_raise = e

    try:
        wrapped = "[" + raw.rstrip(",") + "]"
        parsed_list = json.loads(wrapped)
        if isinstance(parsed_list, list) and parsed_list and all(
            isinstance(item, dict) and "function" in item for item in parsed_list
        ):
            print("[ДИАГНОСТИКА] Ответ был без внешней обёртки — восстановлен как список транзакций.")
            return {
                "scenario_name": "восстановлено из ответа без обёртки",
                "target_invariant": "неизвестно (обёртка потеряна в ответе LLM)",
                "transactions": parsed_list,
                "expected_violation": "н/д",
            }
    except json.JSONDecodeError:
        pass

    raise error_to_raise


def ask_llm(prompt):
    # "format": "json" — режим ограниченной генерации в Ollama: движок
    # физически не может выдать токен, который сломает валидность JSON
    # (незакрытую скобку, комментарий, нумерованный список и т.п.).
    # Это устраняет ПРИЧИНУ большинства infra_error из предыдущих серий,
    # а не лечит симптом постфактум, как наши регексы ниже. При этом
    # НЕ ограничивает содержание ответа — какие функции вызывать, в
    # каком порядке, какие суммы использовать — это остаётся полностью
    # на усмотрение модели. Регекс-починки (sanitize_llm_json,
    # try_parse_scenario) оставляем как страховку на случай, если
    # модель вернёт синтаксически валидный, но структурно неожиданный
    # JSON (например, без нужных ключей).
    response = requests.post(
        OLLAMA_URL,
        json={"model": "llama3", "prompt": prompt, "stream": False, "format": "json"},
        timeout=OLLAMA_TIMEOUT,
    )
    response_json = response.json()

    if "response" not in response_json:
        raise RuntimeError(f"Ollama не вернула поле 'response'. Полный ответ: {response_json}")

    raw = response_json["response"].strip()

    if not raw:
        raise RuntimeError(
            f"Ollama вернула ПУСТОЙ ответ. HTTP статус: {response.status_code}. "
            f"Полный JSON ответа: {response_json}. "
            f"Длина промпта (символов): {len(prompt)}"
        )

    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    raw = raw.strip()

    brace_start = raw.find("{")
    brace_end   = raw.rfind("}")
    if brace_start != -1 and brace_end != -1 and brace_end > brace_start:
        raw = raw[brace_start:brace_end + 1]

    # Модель иногда вставляет JS-style комментарии (// ... ) — валидный
    # JSON комментариев не поддерживает вообще. Вырезаем "// до конца
    # строки" и /* блочные */ комментарии ДО попытки парсинга. Для
    # наших данных (алиасы адресов, числа в wei) это безопасно — такие
    # значения не содержат "//" по смыслу задачи.
    raw = re.sub(r'/\*.*?\*/', '', raw, flags=re.DOTALL)
    raw = re.sub(r'//[^\n]*', '', raw)

    # Модель иногда забывает закрывающую "]" у массива "transactions"
    # (не только "}" у объектов) — например, обрывает последний элемент
    # массива на "}}"  вместо "}]}". ВАЖНО: скобку "]" нужно вставить
    # ПЕРЕД последней "}", а не просто дописать в конец строки — иначе
    # получится "...}}]" (массив как будто закрылся ПОСЛЕ объекта,
    # что синтаксически неверно). Формально: "}}" на конце значит
    # "закрылся последний элемент массива, затем закрылся внешний
    # объект" — а массив забыли закрыть МЕЖДУ ними.
    missing_brackets = raw.count("[") - raw.count("]")
    if missing_brackets > 0:
        if raw.endswith("}"):
            raw = raw[:-1] + ("]" * missing_brackets) + "}"
        else:
            raw += "]" * missing_brackets

    missing_braces = raw.count("{") - raw.count("}")
    if missing_braces > 0:
        raw += "}" * missing_braces
    raw = sanitize_llm_json(raw)

    try:
        return try_parse_scenario(raw)
    except json.JSONDecodeError:
        print(f"\n[ДИАГНОСТИКА] Не удалось распарсить JSON. Сырой ответ модели:\n{raw}\n")
        raise


# ---------------------------------------------------------------------------
# 6. Один этап фаззинга (используется дважды — для blind и для guided)
# ---------------------------------------------------------------------------

def run_stage(sol_file: str, mode: str, max_iterations: int):
    """
    Прогоняет ОДИН этап (blind ИЛИ guided) с чистой историей попыток.
    Возвращает report (если нашли баг) или None (если не нашли за
    max_iterations итераций в рамках этого этапа).
    """
    history = []

    for iteration in range(1, max_iterations + 1):
        print(f"\n--- [{mode}] Итерация {iteration}/{max_iterations} ---")
        prompt   = build_initial_prompt(mode) if iteration == 1 else build_feedback_prompt(history, mode)
        scenario = ask_llm(prompt)
        print(f"Сценарий: {scenario.get('scenario_name')}")
        print(f"Цель: {scenario.get('target_invariant')}")
        txs_str = " → ".join(
            f"{t['function']}({','.join(str(a) for a in t.get('args', []))})"
            for t in scenario["transactions"]
        )
        print(f"Транзакции: {txs_str}")

        bridge, attacker_contract = deploy_bridge_and_attacker(sol_file)
        result = execute_scenario(bridge, attacker_contract, scenario["transactions"])
        history.append({"transactions": scenario["transactions"], "result": result})

        for i, step in enumerate(result["steps"], 1):
            print(f"   [{i}] {step['tx']['function']}({','.join(str(a) for a in step['tx'].get('args', []))}) -> {step['status']}")

        if result["violations"]:
            print(f"\n🚨 БАГ НАЙДЕН на итерации {iteration} (режим: {mode})!")
            for v in result["violations"]:
                print(f"   {v}")
            return {
                "contract": "SimpleBridge",
                "mode": mode,
                "found_on_iteration": iteration,
                "scenario": scenario,
                "violations": result["violations"],
                "steps": result["steps"],
            }

        print("   Нарушений нет, передаём фидбек в LLM...")

    print(f"\n⚠️ Этап '{mode}' завершён без результата за {max_iterations} итераций.")
    return None


# ---------------------------------------------------------------------------
# 7. Каскад: сначала blind, потом (при неудаче) guided с нуля
# ---------------------------------------------------------------------------

def run_fuzzer(sol_file: str = SOL_FILE,
               max_iterations_blind: int = MAX_ITERATIONS_BLIND,
               max_iterations_guided: int = MAX_ITERATIONS_GUIDED) -> dict | None:
    """
    Главная функция прогона. Возвращает report с дополнительным полем
    "stage":
        "blind"      — баг найден самостоятельно, без подсказки
        "guided"     — баг найден только после того, как дали подсказку
        отсутствует  — функция вернула None, баг не найден даже с подсказкой
    """
    print(f"\n{'='*55}\n  AI-FUZZER — SimpleBridge (каскад blind -> guided)\n{'='*55}")

    print("\n### ЭТАП 1: без подсказки (blind) ###")
    report = run_stage(sol_file, mode="blind", max_iterations=max_iterations_blind)
    if report:
        report["stage"] = "blind"
        _save_report(report)
        return report

    print("\n### ЭТАП 1 не дал результата. ЭТАП 2: с подсказкой (guided), история с нуля ###")
    report = run_stage(sol_file, mode="guided", max_iterations=max_iterations_guided)
    if report:
        report["stage"] = "guided"
        _save_report(report)
        return report

    print("\n### Баг НЕ найден даже с подсказкой ###")
    _save_not_found()
    return None


def _save_report(report: dict):
    import os
    os.makedirs("build", exist_ok=True)
    with open("build/fuzzer_bridge_report.json", "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"✅ Отчёт сохранён: build/fuzzer_bridge_report.json (stage={report['stage']})")


def _save_not_found():
    import os
    os.makedirs("build", exist_ok=True)
    with open("build/fuzzer_bridge_report.json", "w") as f:
        json.dump({"contract": "SimpleBridge", "stage": "not_found"}, f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    run_fuzzer()