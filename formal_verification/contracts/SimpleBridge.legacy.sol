// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Упрощённая модель L1-части моста для исследовательского стенда.
/// Не использовать в production.
contract SimpleBridge {
    address public immutable operator;

    uint256 public totalLockedL1;
    uint256 public totalMintedL2;

    mapping(uint256 => bool) public processedWithdrawals;
    mapping(address => uint256) public depositedBy;

    event DepositInitiated(
        address indexed sender,
        address indexed l2Recipient,
        uint256 amount,
        uint256 nonce
    );

    event WithdrawalFinalized(
        address indexed recipient,
        uint256 amount,
        uint256 nonce
    );

    error ZeroAmount();
    error Unauthorized();
    error AlreadyProcessed();
    error InsufficientCollateral();
    error TransferFailed();

    modifier onlyOperator() {
        if (msg.sender != operator) revert Unauthorized();
        _;
    }

    constructor(address operator_) {
        require(operator_ != address(0), "zero operator");
        operator = operator_;
    }

    function deposit(address l2Recipient, uint256 nonce) external payable {
        if (msg.value == 0) revert ZeroAmount();

        depositedBy[msg.sender] += msg.value;
        totalLockedL1 += msg.value;

        // В модели предполагается, что L2-mint соответствует сообщению депозита.
        totalMintedL2 += msg.value;

        emit DepositInitiated(msg.sender, l2Recipient, msg.value, nonce);
    }

    /// @dev Намеренно небезопасный порядок effects/interactions:
    /// nonce отмечается после внешнего вызова.
    function finalizeWithdrawal(
        address payable recipient,
        uint256 amount,
        uint256 nonce
    ) external onlyOperator {
        if (amount == 0) revert ZeroAmount();
        if (processedWithdrawals[nonce]) revert AlreadyProcessed();
        if (amount > totalLockedL1) revert InsufficientCollateral();

        (bool ok, ) = recipient.call{value: amount}("");
        if (!ok) revert TransferFailed();

        processedWithdrawals[nonce] = true;
        totalLockedL1 -= amount;

        // Абстрактная модель burn на L2.
        if (amount <= totalMintedL2) {
            totalMintedL2 -= amount;
        }

        emit WithdrawalFinalized(recipient, amount, nonce);
    }

    receive() external payable {}
}
