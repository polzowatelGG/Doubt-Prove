// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Общая L1-модель моста для исследования reentrancy.
/// Не использовать в production.
contract SimpleBridge {
    address public immutable operator;
    address public receiver;

    address[] public validators;
    mapping(address => bool) public isValidator;

    uint256 public totalLocked;
    uint256 public totalMinted;

    mapping(bytes32 => bool) public processedMessages;
    mapping(bytes32 => uint256) public withdrawalCount;
    mapping(address => uint256) public depositedBy;

    event DepositInitiated(address indexed sender, address indexed l2Recipient, uint256 amount, uint256 nonce);
    event WithdrawalProcessed(address indexed recipient, uint256 amount, bytes32 indexed messageId);

    error ZeroAmount();
    error Unauthorized();
    error AlreadyProcessed();
    error InsufficientCollateral();
    error TransferFailed();

    modifier onlyValidator() {
        if (!isValidator[msg.sender]) revert Unauthorized();
        _;
    }

    constructor(address operator_, address[] memory validators_) {
        require(operator_ != address(0), "zero operator");
        operator = operator_;
        for (uint256 i = 0; i < validators_.length; ++i) {
            address validator = validators_[i];
            if (validator != address(0) && !isValidator[validator]) {
                validators.push(validator);
                isValidator[validator] = true;
            }
        }
    }

    function addValidator(address who) external {
        if (msg.sender != operator) revert Unauthorized();
        if (who != address(0) && !isValidator[who]) {
            validators.push(who);
            isValidator[who] = true;
        }
    }

    function setReceiver(address receiver_) external onlyValidator {
        receiver = receiver_;
    }

    function deposit() external payable {
        if (msg.value == 0) revert ZeroAmount();
        depositedBy[msg.sender] += msg.value;
        totalLocked += msg.value;
        totalMinted += msg.value;
    }

    /// @dev Уязвимая последовательность effects/interactions:
    /// processedMessages отмечается после внешнего вызова.
    function withdraw(address payable recipient, uint256 amount, bytes32 messageId) external onlyValidator {
        if (amount == 0) revert ZeroAmount();
        if (processedMessages[messageId]) revert AlreadyProcessed();
        if (amount > totalLocked) revert InsufficientCollateral();

        withdrawalCount[messageId] += 1;

        (bool ok, ) = recipient.call{value: amount}("");
        if (!ok) revert TransferFailed();

        processedMessages[messageId] = true;
        totalLocked -= amount;
        if (amount <= totalMinted) totalMinted -= amount;

        emit WithdrawalProcessed(recipient, amount, messageId);
    }

    receive() external payable {}
}
