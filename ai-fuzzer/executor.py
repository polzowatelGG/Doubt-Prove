from web3 import Web3
from solcx import compile_source, install_solc
import json

w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
assert w3.is_connected(), "Anvil не запущен!"

ATTACKER = w3.eth.accounts[0]
VICTIM   = w3.eth.accounts[1]
ACCOUNTS = {"attacker": ATTACKER, "victim": VICTIM}

def deploy_contract(sol_file: str, contract_name: str) -> object:
    install_solc("0.8.0")
    with open(sol_file) as f:
        source = f.read()
    compiled = compile_source(source, output_values=["abi", "bin"], solc_version="0.8.0")
    data = compiled[f"<stdin>:{contract_name}"]
    Contract = w3.eth.contract(abi=data["abi"], bytecode=data["bin"])
    tx = Contract.constructor().transact({"from": ATTACKER})
    receipt = w3.eth.wait_for_transaction_receipt(tx)
    print(f"Контракт задеплоен: {receipt['contractAddress']}")
    return w3.eth.contract(address=receipt["contractAddress"], abi=data["abi"])

def check_invariants(contract, sender: str) -> list:
    violations = []
    addr  = w3.to_checksum_address(sender)
    balance         = contract.functions.balances(addr).call()
    total           = contract.functions.totalDeposits().call()
    eth_on_contract = w3.eth.get_balance(contract.address)

    if balance < 0:
        violations.append(f"НАРУШЕНИЕ: balances[attacker] < 0 ({balance})")
    if total > eth_on_contract:
        violations.append(
            f"НАРУШЕНИЕ: totalDeposits ({total} wei) > ETH на контракте ({eth_on_contract} wei)"
        )
    if balance > total:
        violations.append(
            f"НАРУШЕНИЕ: balance аккаунта ({balance}) > totalDeposits ({total})"
        )
    return violations

def execute_tx(contract, tx: dict) -> dict:
    fn_name = tx["function"]
    args    = tx.get("args", [])
    sender  = ACCOUNTS.get(tx.get("sender", "attacker"), ATTACKER)

    print(f"\n→ {fn_name}({', '.join(str(a) for a in args)}) от {tx.get('sender','attacker')}")

    try:
        fn = getattr(contract.functions, fn_name)
        if fn_name == "deposit":
            value = int(args[0]) if args else 100
            fn().transact({"from": sender, "value": value})
        elif fn_name == "getBalance":
            result = fn().call({"from": sender})
            print(f"  getBalance() = {result} wei")
            return {"status": "view", "result": result}
        else:
            fn(*[int(a) for a in args]).transact({"from": sender})
        print(f"  ✅ успешно")
        return {"status": "success"}
    except Exception as e:
        print(f"  ❌ revert: {e}")
        return {"status": "revert", "error": str(e)}

def run_scenario(scenario_file: str, sol_file: str, contract_name: str):
    with open(scenario_file) as f:
        scenario = json.load(f)

    print(f"Сценарий:  {scenario['scenario_name']}")
    print(f"Цель:      {scenario['target_invariant']}")
    print(f"Ожидание:  {scenario.get('expected_violation', '—')}\n")

    contract = deploy_contract(sol_file, contract_name)
    found_violations = []

    for i, tx in enumerate(scenario["transactions"], 1):
        print(f"[Шаг {i}/{len(scenario['transactions'])}]")
        execute_tx(contract, tx)
        violations = check_invariants(contract, ATTACKER)
        if violations:
            print(f"\n🚨 НАЙДЕНО НАРУШЕНИЕ ИНВАРИАНТА:")
            for v in violations:
                print(f"   {v}")
            found_violations.extend(violations)
        else:
            bal   = contract.functions.balances(ATTACKER).call()
            total = contract.functions.totalDeposits().call()
            eth   = w3.eth.get_balance(contract.address)
            print(f"  инварианты OK | balance={bal} wei | totalDeposits={total} wei | ETH на контракте={eth} wei")

    print("\n" + "="*50)
    if found_violations:
        print("🚨 ИТОГ: инварианты нарушены!")
        for v in found_violations:
            print(f"  {v}")
    else:
        print("✅ ИТОГ: все инварианты соблюдены. Уязвимостей не найдено.")

    return found_violations

if __name__ == "__main__":
    import sys
    sol_file      = sys.argv[1] if len(sys.argv) > 1 else "contracts/VulnerableVault.sol"
    contract_name = sys.argv[2] if len(sys.argv) > 2 else "VulnerableVault"
    run_scenario("build/attack_scenario.json", sol_file, contract_name)