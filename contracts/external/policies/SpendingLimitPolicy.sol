// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "contracts/DataTypes.sol";
import { IActionPolicy } from "contracts/interfaces/IPolicy.sol";

import { IERC20 } from "forge-std/interfaces/IERC20.sol";

address constant NATIVE_TOKEN = address(0);

uint256 constant VALIDATION_SUCCESS = 0;
uint256 constant VALIDATION_FAILED = 1;

contract SpendingLimitPolicy is IActionPolicy {
    event TokenSpent(ConfigId id, address multiplexer, address token, address account, uint256 amount);

    error InvalidTokenAddress(address token);

    struct TokenPolicyData {
        uint256 alreadySpent;
        uint256 spendingLimit;
    }

    mapping(
        ConfigId id
            => mapping(address msgSender => mapping(address token => mapping(address userOpSender => TokenPolicyData)))
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
    }

    function onInstall(bytes calldata data) external override { }

    function initializeWithMultiplexer(address account, ConfigId configId, bytes calldata initData) external { }

    function onUninstall(bytes calldata data) external override { }

    function isModuleType(uint256 moduleTypeId) external view override returns (bool) { }

    function isInitialized(address smartAccount) external view override returns (bool) { }

    function isInitialized(address account, ConfigId id) external view override returns (bool) { }

    function isInitialized(address account, address multiplexer, ConfigId id) external view override returns (bool) { }

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
            address from;
            (, from, amount) = abi.decode(callData[4:], (address, address, uint256));
            if (from != account) revert();
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
            return VALIDATION_SUCCESS;
        }
    }
}
