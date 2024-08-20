// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "contracts/DataTypes.sol";
import { IActionPolicy } from "contracts/interfaces/IPolicy.sol";

import { IERC20 } from "forge-std/interfaces/IERC20.sol";

address constant NATIVE_TOKEN = address(0xeEeeeeEeEeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE);

uint256 constant VALIDATION_SUCCESS = 0;
uint256 constant VALIDATION_FAILED = 1;

contract TokenPolicy is IActionPolicy {
    event TokenSpent(SessionId id, address token, address account, uint256 amount);

    error InvalidTokenAddress(address token);

    struct TokenPolicyData {
        uint256 alreadySpent;
        uint256 spendingLimit;
    }

    mapping(
        SessionId id
            => mapping(address msgSender => mapping(address token => mapping(address userOpSender => TokenPolicyData)))
    ) internal $policyData;

    function _getPolicy(
        SessionId id,
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

    function onUninstall(bytes calldata data) external override { }

    function isModuleType(uint256 moduleTypeId) external view override returns (bool) { }

    function isInitialized(address smartAccount) external view override returns (bool) { }

    function isInitialized(address account, SessionId id) external view override returns (bool) { }

    function isInitialized(address multiplexer, address account, SessionId id) external view override returns (bool) { }

    function isInitialized(address multiplexer, address account) external view override returns (bool) { }

    function checkAction(
        SessionId id,
        address target,
        uint256 value,
        bytes calldata callData,
        PackedUserOperation calldata op
    )
        external
        override
        returns (uint256)
    {
        uint256 amount;
        address token;
        bytes4 functionSelector;

        if (callData.length == 0 && value != 0) {
            amount = value;
            token = NATIVE_TOKEN;
        } else {
            functionSelector = bytes4(callData[0:4]);

            if (functionSelector == IERC20.approve.selector) {
                token = target;
                (, amount) = abi.decode(callData[4:], (address, uint256));
            } else if (functionSelector == IERC20.transfer.selector) {
                token = target;
                (, amount) = abi.decode(callData[4:], (address, uint256));
            } else if (functionSelector == IERC20.transferFrom.selector) {
                token = target;
                address from;
                (, from, amount) = abi.decode(callData[4:], (address, address, uint256));
                if (from != op.sender) revert("TokenPolicy: transferFrom sender must be userOp.sender");
            }
        }
        if (amount == 0) return VALIDATION_SUCCESS;

        TokenPolicyData storage $ = _getPolicy({ id: id, userOpSender: op.sender, token: token });

        uint256 spendingLimit = $.spendingLimit;
        uint256 alreadySpent = $.alreadySpent;

        uint256 newAmount = alreadySpent + amount;

        if (newAmount > spendingLimit) {
            return VALIDATION_FAILED;
        } else {
            $.alreadySpent = newAmount;
            emit TokenSpent(id, token, op.sender, amount);
            return VALIDATION_SUCCESS;
        }
    }
}
