// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "../../DataTypes.sol";
import { IActionPolicy, IPolicy, VALIDATION_SUCCESS, VALIDATION_FAILED } from "../../interfaces/IPolicy.sol";
import { IERC20 } from "forge-std/interfaces/IERC20.sol";
import { IERC165 } from "forge-std/interfaces/IERC165.sol";
import { EnumerableSet } from "../../utils/EnumerableSet4337.sol";

/**
 * @title ERC20SpendingLimitPolicy
 * @notice A policy that allows transferring and approving ERC20 tokens up to a certain limit.
 * @dev Every config can allow multiple tokens with its own limit each.
 */
contract ERC20SpendingLimitPolicy is IActionPolicy {
    using EnumerableSet for EnumerableSet.AddressSet;

    event TokenSpent(
        ConfigId id, address multiplexer, address token, address account, uint256 amount, uint256 remaining
    );

    error InvalidTokenAddress(address token);
    error InvalidLimit(uint256 limit);
    error InvalidInitDataLength();

    struct TokenPolicyData {
        uint256 alreadySpent;
        uint256 approvedAmount;
        uint256 spendingLimit;
    }

    mapping(ConfigId id => mapping(address multiplexer => EnumerableSet.AddressSet tokensEnabled)) internal $tokens;
    mapping(
        ConfigId id
            => mapping(
                address mulitplexer => mapping(address token => mapping(address userOpSender => TokenPolicyData))
            )
    ) internal $policyData;

    /**
     * Initializes the policy to be used by given account through multiplexer (msg.sender) such as Smart Sessions.
     * Overwrites state.
     * @notice ATTENTION: This method is called during permission installation as part of the enabling policies flow.
     * A secure policy would minimize external calls from this method (ideally, to 0) to prevent passing control flow to
     * external contracts.
     */
    function initializeWithMultiplexer(address account, ConfigId configId, bytes calldata initData) external {
        (address[] memory tokens, uint256[] memory limits) = abi.decode(initData, (address[], uint256[]));
        EnumerableSet.AddressSet storage $t = $tokens[configId][msg.sender];
        require(tokens.length == limits.length, InvalidInitDataLength());

        uint256 length_i = $t.length(account);

        // if there's some inited tokens, clear storage first
        if (length_i > 0) {
            for (uint256 i; i < length_i; i++) {
                // for all tokens which have been inited for a given configId and mxer
                address token = $t.at(account, i);
                TokenPolicyData storage $ = _getPolicy({ id: configId, userOpSender: account, token: token });
                // clear limit and spent
                $.spendingLimit = 0;
                $.alreadySpent = 0;
                $.approvedAmount = 0;
            }
            // clear inited tokens
            $t.removeAll(account);
        }

        // set new
        for (uint256 i; i < tokens.length; i++) {
            address token = tokens[i];
            uint256 limit = limits[i];
            if (token == address(0)) revert InvalidTokenAddress(token);
            if (limit == 0) revert InvalidLimit(limit);
            TokenPolicyData storage $ = _getPolicy({ id: configId, userOpSender: account, token: token });
            // set limit
            $.spendingLimit = limit;
            // mark token as inited
            $t.add(account, token);
        }
        emit IPolicy.PolicySet(configId, msg.sender, account);
    }

    /**
     * @notice Checks if the action is valid according to the policy.
     * @param id The config ID.
     * @param account The account address.
     * @param target The target address.
     * @param value The value.
     * @param callData The call data.
     * @return The validation result.
     */
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
        (bool isTokenTransfer, uint256 amount) = _isTokenTransferOrApprove(account, callData);
        if (!isTokenTransfer) return VALIDATION_FAILED;

        TokenPolicyData storage $ = _getPolicy({ id: id, userOpSender: account, token: target });

        // Use a struct here to avoid stack too deep :)
        TokenPolicyData memory newData = TokenPolicyData({
            alreadySpent: $.alreadySpent,
            approvedAmount: $.approvedAmount,
            spendingLimit: $.spendingLimit
        });

        uint256 totalSpentAndApproved;

        if (
            bytes4(callData[0:4]) == IERC20.approve.selector || bytes4(callData[0:4]) == bytes4(0x39509351) // increaseAllowance(address,uint256)
        ) {
            // increase approval case
            // if the amount is uint256 max (max alowance) and the $.approvedAmount is not 0,
            // it will overflow and revert. In theory this is not what should happen as the approval in erc20
            // contract can be successfully set to max in this case, and if the previous approval was not yet spent,
            // can be a valid case, however accounting for it will cause so many other edge cases and security
            // considerations
            // that we decided to stick with this approach and document the fact that the session key should never
            // operate with max allowances
            // in fact it has no reasons of doing this as the purpose of session key is that it can issue whatever
            // amount of signature, without
            // making UX worse for user. So it is recommended that a session key always permits the exact amount of
            // tokens that is about to be spent by spender.
            newData.approvedAmount += amount;
            totalSpentAndApproved = newData.alreadySpent + newData.approvedAmount;
            // Validate before updating storage, early return if the total spent and approved exceeds the limit
            if (totalSpentAndApproved > newData.spendingLimit) {
                return VALIDATION_FAILED;
            }
            // Only update storage after validation passes
            $.approvedAmount = newData.approvedAmount;
        } else {
            // transfer or transferFrom case
            newData.alreadySpent += amount;
            totalSpentAndApproved = newData.alreadySpent + newData.approvedAmount;
            // Validate before updating storage, early return if the total spent and approved exceeds the limit
            if (totalSpentAndApproved > newData.spendingLimit) {
                return VALIDATION_FAILED;
            }
            // Only update storage after validation passes
            $.alreadySpent = newData.alreadySpent;
        }

        emit TokenSpent(id, msg.sender, target, account, amount, newData.spendingLimit - totalSpentAndApproved);
        return VALIDATION_SUCCESS;
    }

    /**
     *
     */

    /**
     * @notice Returns the limit and spent amount for a given token under permission, account, multiplexer.
     * @param id The config ID.
     * @param multiplexer The multiplexer address.
     * @param token The token address.
     * @param userOpSender The user operation sender address.
     * @return spendingLimit The spending limit.
     * @return alreadySpent The already spent amount.
     * @return approvedAmount The approved amount.
     */
    function getPolicyData(
        ConfigId id,
        address multiplexer,
        address token,
        address userOpSender
    )
        external
        view
        returns (uint256 spendingLimit, uint256 alreadySpent, uint256 approvedAmount)
    {
        if (token == address(0)) revert InvalidTokenAddress(token);
        if (!$tokens[id][multiplexer].contains(userOpSender, token)) {
            revert InvalidTokenAddress(token);
        }
        TokenPolicyData memory $ = $policyData[id][multiplexer][token][userOpSender];
        return ($.spendingLimit, $.alreadySpent, $.approvedAmount);
    }

    /**
     * @notice Supports the IERC165 interface.
     * @param interfaceID The interface ID.
     * @return True if the interface is supported, false otherwise.
     */
    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return (
            interfaceID == type(IERC165).interfaceId || interfaceID == type(IPolicy).interfaceId
                || interfaceID == type(IActionPolicy).interfaceId
        );
    }

    /**
     * @notice Checks if the call is a token transfer.
     * @param account The account address.
     * @param callData The call data.
     * @dev we do not check if the transfer is from self to self, as this should not be allowed by token itself
     * returns bool => isTransfer, amount spent
     */
    function _isTokenTransferOrApprove(
        address account,
        bytes calldata callData
    )
        internal
        pure
        returns (bool, uint256)
    {
        bytes4 functionSelector = bytes4(callData[0:4]);

        if (functionSelector == IERC20.approve.selector) {
            (, uint256 amount) = abi.decode(callData[4:], (address, uint256));
            // if approve is to account itself, it should revert in the token contract
            // otherwise it should spend the limit
            return (true, amount);
        } else if (functionSelector == bytes4(keccak256("increaseAllowance(address,uint256)"))) {
            // increase allowance is deprecated interface by OZ, can be used by some tokens
            (, uint256 amount) = abi.decode(callData[4:], (address, uint256));
            return (true, amount);
        } else if (functionSelector == IERC20.transfer.selector) {
            (, uint256 amount) = abi.decode(callData[4:], (address, uint256));
            // if transfer is to account, it should revert in the token contract
            // otherwise it should spend the limit
            return (true, amount);
        } else if (functionSelector == IERC20.transferFrom.selector) {
            (, address to, uint256 amount) = abi.decode(callData[4:], (address, address, uint256));
            if (to == account) {
                // if transfer is from and to account, it should revert in the token contract
                // if transfer is from somewhere to account, it should not spend the limit, so amount is 0
                return (true, 0);
            }
            // from is account and to is not => spend tokens from account
            // or from is not account and to is not => spend approved tokens also considered as spending the limit
            return (true, amount);
        }
        return (false, 0);
    }

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
}
