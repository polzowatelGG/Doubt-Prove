// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./SimpleBridge.sol";

/// @title SimpleBridgeEchidnaTest — harness для сравнения Echidna vs LLM-фаззера
///
/// ВАЖНО (исправлено после ревью): в первой версии receive() реентрировал
/// БЕЗУСЛОВНО при получении любого ETH — это делало атаку доступной без
/// какого-либо "решения" со стороны Echidna, тогда как LLM в Фазе 6.5
/// должна была САМА вызвать setAttackParams(...) с maxReentries>0, чтобы
/// включить реентранси (по умолчанию MaliciousReceiver.receive() ничего
/// не делает). Без этой правки сравнение было бы нечестным: Echidna решала
/// бы более простую задачу (найти порядок из 2 вызовов), чем модель
/// (найти порядок из 3 вызовов с правильной конфигурацией). Теперь
/// реентранси требует явного вызова armReentry() — прямой аналог
/// setAttackParams(), так что обеим сторонам нужно "додуматься" до
/// одинакового числа логических шагов.
contract SimpleBridgeEchidnaTest {
    SimpleBridge public bridge;

    bytes32 public currentMessageId;
    uint256 private nonce;

    uint8 public reentryCount;
    uint8 public maxReentries; // 0 по умолчанию = атака ВЫКЛЮЧЕНА, как и у MaliciousReceiver

    mapping(bytes32 => uint256) public withdrawHits;

    constructor() {
        address[] memory validators = new address[](1);
        validators[0] = address(this);
        bridge = new SimpleBridge(validators);
        currentMessageId = keccak256(abi.encodePacked(nonce));
    }

    // ── Функции, которые Echidna будет вызывать в случайном порядке ──

    function newMessage() public {
        nonce++;
        currentMessageId = keccak256(abi.encodePacked(nonce));
        reentryCount = 0;
    }

    function doDeposit() public payable {
        require(msg.value > 0);
        bridge.deposit{value: msg.value}();
    }

    /// Прямой аналог setAttackParams() у MaliciousReceiver — ОБЯЗАТЕЛЬНЫЙ
    /// шаг для включения реентранси. Echidna должна сама случайно набрести
    /// на вызов этой функции с _maxReentries > 0, точно так же как модели
    /// нужно было самой решить вызвать setAttackParams с ненулевым значением.
    function armReentry(uint8 _maxReentries) public {
        maxReentries = _maxReentries;
    }

    function doWithdraw(uint256 amount) public {
        require(amount > 0);
        reentryCount = 0;
        bridge.withdraw(payable(address(this)), amount, currentMessageId);
    }

    /// Теперь реентрирует ТОЛЬКО если атака была явно включена через
    /// armReentry() — до этого receive() просто пассивно принимает ETH,
    /// как обычный контракт без злого умысла.
    receive() external payable {
        withdrawHits[currentMessageId] += 1;
        if (maxReentries > 0 && reentryCount < maxReentries) {
            reentryCount++;
            try bridge.withdraw(payable(address(this)), msg.value, currentMessageId) {} catch {}
        }
    }

    // ── Инварианты-свойства для Echidna ─────────────────────────────

    function echidna_no_double_withdraw() public view returns (bool) {
        return withdrawHits[currentMessageId] <= 1;
    }

    function echidna_locked_never_exceeds_balance() public view returns (bool) {
        return bridge.totalLocked() <= address(bridge).balance;
    }

    function echidna_locked_equals_minted() public view returns (bool) {
        return bridge.totalLocked() == bridge.totalMinted();
    }
}
