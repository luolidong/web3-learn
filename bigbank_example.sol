// SPDX-License-Identifier: MIT

-- 编写 IBank 接口及BigBank 合约，使其满足 Bank 实现 IBank， BigBank 继承自 Bank ， 同时 BigBank 有附加要求：

-- 要求存款金额 >0.001 ether（用modifier权限控制）
-- BigBank 合约支持转移管理员
-- 编写一个 Admin 合约， Admin 合约有自己的 Owner ，同时有一个取款函数 adminWithdraw(IBank bank) , adminWithdraw 中会调用 IBank 接口的 withdraw 方法从而把 bank 合约内的资金转移到 Admin 合约地址。

-- BigBank 和 Admin 合约 部署后，把 BigBank 的管理员转移给 Admin 合约地址，模拟几个用户的存款，然后

-- Admin 合约的Owner地址调用 adminWithdraw(IBank bank) 把 BigBank 的资金转移到 Admin 地址。

-- 难点：需调用bigbank的transfer方法，将资金从bigbank合约地址转移到admin合约地址，即使 Admin.owner 和 BigBank.admin 都是同一个用户地址，当 Admin.adminWithdraw() 调用 bank.withdraw() 时， msg.sender 变成了 Admin 合约地址 ，而不是用户地址。

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