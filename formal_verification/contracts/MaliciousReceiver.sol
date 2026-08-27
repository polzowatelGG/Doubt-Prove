// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ISimpleBridge {
    function withdraw(address payable recipient, uint256 amount, bytes32 messageId) external;
}

/// @notice Злонамеренный получатель для воспроизведения nested call/reentrancy.
contract MaliciousReceiver {
    ISimpleBridge public immutable bridge;
    bool public entered;
    uint256 public attackAmount;
    bytes32 public attackMessageId;

    constructor(address bridge_) {
        require(bridge_ != address(0), "zero bridge");
        bridge = ISimpleBridge(bridge_);
    }

    function configure(uint256 amount, bytes32 messageId) external {
        attackAmount = amount;
        attackMessageId = messageId;
        entered = false;
    }

    receive() external payable {
        if (!entered && attackAmount != 0) {
            entered = true;
            bridge.withdraw(payable(address(this)), attackAmount, attackMessageId);
        }
    }
}
