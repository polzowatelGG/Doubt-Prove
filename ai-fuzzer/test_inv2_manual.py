"""
test_inv2_manual.py — проверка INV-2 БЕЗ какой-либо атаки.

Смысл: в 30-прогонной серии всплыл подозрительный случай — INV-2
(totalLocked == totalMinted) был "нарушен" в прогоне, где ВСЕ withdraw
упали с revert (реентранси не сработала). Если totalLocked/totalMinted
расходятся уже после ОДНОГО чистого deposit() без всякой атаки — значит
дело не в найденной уязвимости, а либо в том, как устроен контракт
(totalMinted не привязан 1:1 к deposit), либо в том, как сформулирован
сам инвариант в check_invariants().

Сценарий:
  1. Деплоим свежий bridge + attacker_contract (как обычно).
  2. Вызываем ТОЛЬКО deposit(1000) от attacker. Ничего больше.
  3. Смотрим totalLocked, totalMinted, реальный ETH-баланс контракта.
  4. Прогоняем check_invariants() и смотрим, нарушено ли что-то.

Если после шага 2 totalLocked != totalMinted — это значит, что в
SimpleBridge.sol минтинг НЕ происходит автоматически при deposit(), и
INV-2 в текущей формулировке ломается тривиально, без всякой атаки.
Это нужно знать ДО того, как писать выводы про находки фаззера.

Запуск:
    source venv/bin/activate
    python test_inv2_manual.py
"""

from fuzzer_bridge import w3, ATTACKER, deploy_bridge_and_attacker, check_invariants


def main():
    bridge, attacker_contract = deploy_bridge_and_attacker("contracts/SimpleBridge.sol")
    print(f"Bridge deployed at: {bridge.address}")

    print("\nСостояние СРАЗУ ПОСЛЕ ДЕПЛОЯ (до какого-либо deposit):")
    print(f"  totalLocked  = {bridge.functions.totalLocked().call()}")
    print(f"  totalMinted  = {bridge.functions.totalMinted().call()}")
    print(f"  ETH на мосту = {w3.eth.get_balance(bridge.address)}")

    print("\nВызываем ТОЛЬКО deposit(1000) от attacker, больше ничего...")
    tx = bridge.functions.deposit().transact({"from": ATTACKER, "value": 1000})
    w3.eth.wait_for_transaction_receipt(tx)   # ждём, пока транзакция реально попадёт в блок —
                                                # без этого возможен "рваный" снимок состояния
                                                # (см. пояснение в чате)

    total_locked  = bridge.functions.totalLocked().call()
    total_minted  = bridge.functions.totalMinted().call()
    eth_on_bridge = w3.eth.get_balance(bridge.address)

    print("\nСостояние ПОСЛЕ одного чистого deposit(1000):")
    print(f"  totalLocked  = {total_locked}")
    print(f"  totalMinted  = {total_minted}")
    print(f"  ETH на мосту = {eth_on_bridge}")

    violations = check_invariants(bridge)
    if violations:
        print("\n🚨 ИНВАРИАНТ НАРУШЕН уже на чистом deposit() без атаки:")
        for v in violations:
            print(f"   {v}")
        print("\n=> Вывод: INV-2 в текущей формулировке нарушается ТРИВИАЛЬНО.")
        print("   Это значит, что deposit() и минтинг не связаны 1:1 в контракте,")
        print("   либо инвариант сформулирован некорректно относительно логики")
        print("   контракта. Проверьте исходник SimpleBridge.sol: функция")
        print("   deposit() должна увеличивать totalMinted, а не только totalLocked.")
    else:
        print("\n✅ Инварианты соблюдены на чистом deposit(). Расхождение из прогона 27")
        print("   значит связано именно с последовательностью вызовов в том сценарии,")
        print("   не с базовым поведением контракта — можно доверять находке фаззера.")


if __name__ == "__main__":
    main()