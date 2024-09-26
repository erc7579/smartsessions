// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "../../DataTypes.sol";
import { IActionPolicy, IPolicy } from "../../interfaces/IPolicy.sol";
import { IERC20 } from "forge-std/interfaces/IERC20.sol";

address constant NATIVE_TOKEN = address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE);

uint256 constant VALIDATION_SUCCESS = 0;
uint256 constant VALIDATION_FAILED = 1;

contract ERC20SpendingLimitPolicy is IActionPolicy {
    event TokenSpent(
        ConfigId id, address multiplexer, address token, address account, uint256 amount, uint256 remaining
    );

    error InvalidTokenAddress(address token);
    error InvalidLimit(uint256 limit);

    struct TokenPolicyData {
        uint256 alreadySpent;
        uint256 spendingLimit;
    }

    mapping(ConfigId id => mapping(address multiplexer => mapping(address userOpSender => bool initialized))) internal
        $initialized;
    mapping(
        ConfigId id
            => mapping(
                address mulitplexer => mapping(address token => mapping(address userOpSender => TokenPolicyData))
            )
    ) internal $policyData;

    function _getPolicy(
        ConfigId id,
        address userOpSender,
        address token
    )
        internal
        view
        returns (TokenPolicyData storage s)
    {
        if (token == address(0)) revert InvalidTokenAddress(token);
        s = $policyData[id][msg.sender][token][userOpSender];
    }

    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        if (interfaceID == type(IActionPolicy).interfaceId) {
            return true;
        }
        if (interfaceID == IActionPolicy.checkAction.selector) {
            return true;
        }
    }

    function initializeWithMultiplexer(address account, ConfigId configId, bytes calldata initData) external {
        (address[] memory tokens, uint256[] memory limits) = abi.decode(initData, (address[], uint256[]));

        for (uint256 i; i < tokens.length; i++) {
            address token = tokens[i];
            uint256 limit = limits[i];
            if (token == address(0)) revert InvalidTokenAddress(token);
            if (limit == 0) revert InvalidLimit(limit);
            TokenPolicyData storage $ = _getPolicy({ id: configId, userOpSender: account, token: token });
            $.spendingLimit = limit;
            $.alreadySpent = 0;
        }
        emit IPolicy.PolicySet(configId, msg.sender, account);
    }

    function _isTokenTransfer(
        address account,
        bytes calldata callData
    )
        internal
        pure
        returns (bool isTransfer, uint256 amount)
    {
        bytes4 functionSelector = bytes4(callData[0:4]);

        if (functionSelector == IERC20.approve.selector) {
            (, amount) = abi.decode(callData[4:], (address, uint256));
            return (true, amount);
        } else if (functionSelector == IERC20.transfer.selector) {
            (, amount) = abi.decode(callData[4:], (address, uint256));
            return (true, amount);
        } else if (functionSelector == IERC20.transferFrom.selector) {
            (,, amount) = abi.decode(callData[4:], (address, address, uint256));
            return (true, amount);
        }
        return (false, 0);
    }

    function checkAction(
        ConfigId id,
        address account,
        address target,
        uint256 value,
        bytes calldata callData
    )
        external
        override
        returns (uint256)
    {
        if (value != 0) return VALIDATION_FAILED;
        (bool isTokenTransfer, uint256 amount) = _isTokenTransfer(account, callData);
        if (!isTokenTransfer) return VALIDATION_FAILED;

        TokenPolicyData storage $ = _getPolicy({ id: id, userOpSender: account, token: target });

        uint256 spendingLimit = $.spendingLimit;
        uint256 alreadySpent = $.alreadySpent;

        uint256 newAmount = alreadySpent + amount;

        if (newAmount > spendingLimit) {
            return VALIDATION_FAILED;
        } else {
            $.alreadySpent = newAmount;

            emit TokenSpent(id, msg.sender, target, account, amount, spendingLimit - newAmount);
            return VALIDATION_SUCCESS;
        }
    }
}
