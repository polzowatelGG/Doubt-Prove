// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableVault {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        payable(msg.sender).transfer(amount);
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
    }

    function getBalance() external view returns (uint256) {
        return balances[msg.sender];
    }
}
