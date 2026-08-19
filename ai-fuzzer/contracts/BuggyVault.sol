// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract BuggyVault {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        balances[msg.sender] -= amount;
        // ⚠️ БАГ: забыли обновить totalDeposits
        // totalDeposits -= amount;  ← эта строка пропущена
        payable(msg.sender).transfer(amount);
    }

    function getBalance() external view returns (uint256) {
        return balances[msg.sender];
    }
}
