/*
 Эталонная CVL-спецификация для общей модели SimpleBridge.
 MaliciousReceiver подключается через links: SimpleBridge.receiver => MaliciousReceiver.
*/

using SimpleBridge as bridge;
using MaliciousReceiver as attacker;

methods {
    function bridge.totalLocked() external returns (uint256) envfree;
    function bridge.totalMinted() external returns (uint256) envfree;
    function bridge.processedMessages(bytes32) external returns (bool) envfree;
    function bridge.withdrawalCount(bytes32) external returns (uint256) envfree;
    function bridge.receiver() external returns (address) envfree;
}

/* Привязка реального receiver к MaliciousReceiver в Certora scene. */
links {
    bridge.receiver => attacker;
}

/* Экономический инвариант состояния. */
invariant collateralCoversMinted()
    bridge.totalMinted() <= bridge.totalLocked();

/* Депозит не должен нарушать покрытие. */
rule depositPreservesCollateral(address recipient, uint256 nonce) {
    env e;
    require e.msg.value > 0;

    bridge.deposit@withrevert(e, recipient, nonce);
    assert !lastReverted => bridge.totalMinted() <= bridge.totalLocked();
}

/* После успешного вывода messageId должен быть помечен. */
rule successfulWithdrawalMarksMessage(
    address payable recipient,
    uint256 amount,
    bytes32 messageId
) {
    env e;
    require bridge.isValidator(e.msg.sender);
    require amount > 0;

    bridge.withdraw@withrevert(e, recipient, amount, messageId);
    assert !lastReverted => bridge.processedMessages(messageId);
}

/*
 * Главное правило:
 * один внешний withdraw с receiver, связанным с MaliciousReceiver.
 * Reentrancy происходит внутри recipient.call(), а не вторым вызовом
 * из CVL. Поэтому проверка выполняется сразу после ОДНОГО вызова.
 */
rule withdrawalMessageCannotBeReentered(
    uint256 amount,
    bytes32 messageId
) {
    env e;
    require bridge.isValidator(e.msg.sender);
    require bridge.receiver() == attacker;
    require amount > 0;
    require bridge.totalLocked() >= amount * 2;

    bridge.withdraw@withrevert(
        e,
        payable(bridge.receiver()),
        amount,
        messageId
    );

    assert !lastReverted => bridge.withdrawalCount(messageId) == 1;
}
