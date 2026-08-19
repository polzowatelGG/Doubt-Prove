from pathlib import Path
import sys

from solcx import compile_source, install_solc, get_installed_solc_versions
from web3 import Web3

SCRIPT_DIR = Path(__file__).resolve().parent
CONTRACT_PATH = SCRIPT_DIR / "contracts" / "SimpleVault.sol"

if not CONTRACT_PATH.exists():
    print(f"Ошибка: файл контракта не найден по пути {CONTRACT_PATH}")
    sys.exit(1)

# Устанавливаем компилятор Solidity, если он ещё не установлен
required_version = "0.8.0"
installed = get_installed_solc_versions()
if required_version not in [str(v) for v in installed]:
    install_solc(required_version)

# Подключаемся к Anvil
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
if not w3.is_connected():
    print("Ошибка: не удалось подключиться к Anvil по адресу http://127.0.0.1:8545")
    sys.exit(1)
print("Подключение к Anvil: OK")

accounts = w3.eth.accounts
if not accounts:
    print("Ошибка: не найдено ни одного аккаунта в Anvil")
    sys.exit(1)

account = accounts[0]
print("Аккаунт:", account)

# Читаем и компилируем контракт
source = CONTRACT_PATH.read_text(encoding="utf-8")
compiled = compile_source(source, output_values=["abi", "bin"], solc_version=required_version)
contract_data = compiled["<stdin>:SimpleVault"]
abi = contract_data["abi"]
bytecode = contract_data["bin"]

# Деплоим контракт
Contract = w3.eth.contract(abi=abi, bytecode=bytecode)
print("Деплой контракта...")
tx_hash = Contract.constructor().transact({"from": account})
receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
contract_address = receipt["contractAddress"]
print("Контракт задеплоен:", contract_address)

# Вызываем deposit() с 1 ETH
contract = w3.eth.contract(address=contract_address, abi=abi)
print("Выполняем deposit(1 ETH)...")
tx = contract.functions.deposit().transact({
    "from": account,
    "value": w3.to_wei(1, "ether")
})
w3.eth.wait_for_transaction_receipt(tx)
print("deposit(1 ETH) — выполнен")

# Читаем состояние контракта
balance = contract.functions.balances(account).call()
total = contract.functions.totalDeposits().call()
print(f"Баланс аккаунта:  {w3.from_wei(balance, 'ether')} ETH")
print(f"Total deposits:   {w3.from_wei(total, 'ether')} ETH")
print("✅ Фаза 2 завершена успешно!")
