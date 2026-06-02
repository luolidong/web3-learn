// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IBank {
    function deposit() external payable;
    function withdraw() external;
    function getBalance() external view returns (uint256);
}

contract Bank is IBank {
    address public admin;
    mapping(address => uint256) public balances;

    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can call this");
        _;
    }

    function deposit() public payable override virtual {
        require(msg.value > 0, "Deposit amount must be greater than 0");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw() external override virtual onlyAdmin {
        uint256 balance = address(this).balance;
        require(balance > 0, "No funds to withdraw");
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Withdraw failed");
        emit Withdraw(msg.sender, balance);
    }

    function getBalance() external view override returns (uint256) {
        return address(this).balance;
    }
}

contract BigBank is Bank {
    modifier minimumDeposit() {
        require(msg.value > 0.001 ether, "Deposit must be greater than 0.001 ether");
        _;
    }

    function deposit() public payable override minimumDeposit {
        super.deposit();
    }

    function transferAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "New admin cannot be zero address");
        admin = newAdmin;
    }
}

contract Admin {
    address public owner;

    event AdminWithdraw(address indexed bankAddress, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this");
        _;
    }

    function adminWithdraw(IBank bank) external onlyOwner {
        uint256 balance = bank.getBalance();
        require(balance > 0, "Bank has no funds");
        bank.withdraw();
        emit AdminWithdraw(address(bank), balance);
    }

    receive() external payable {}

    function getAdminBalance() external view returns (uint256) {
        return address(this).balance;
    }
}