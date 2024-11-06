// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "../../DataTypes.sol";
import { IActionPolicy, IPolicy, VALIDATION_SUCCESS, VALIDATION_FAILED } from "../../interfaces/IPolicy.sol";
import { IERC20 } from "forge-std/interfaces/IERC20.sol";
import { IERC165 } from "forge-std/interfaces/IERC165.sol";
import { EnumerableSet } from "../../utils/EnumerableSet4337.sol";

/**
 * @title ERC20ApprovalLimitPolicy
 * @notice A policy that allows approving ERC20 tokens up to a certain limit.
 * @dev Every config can allow multiple tokens with its own limit each.
 */
contract ERC20ApprovalLimitPolicy is IActionPolicy {
    using EnumerableSet for EnumerableSet.AddressSet;

    event TokenApproved(
        ConfigId id, address multiplexer, address token, address account, uint256 amount, uint256 remaining
    );

    error InvalidTokenAddress(address token);
    error InvalidLimit(uint256 limit);

    struct TokenPolicyData {
        uint256 totalApproved;
        uint256 approvalLimit;
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

        uint256 length_i = $t.length(account);

        // if there's some inited tokens, clear storage first
        if (length_i > 0) {
            for (uint256 i; i < length_i; i++) {
                // for all tokens which have been inited for a given configId and mxer
                address token = $t.at(account, i);
                TokenPolicyData storage $ = _getPolicy({ id: configId, userOpSender: account, token: token });
                // clear limit and spent
                $.approvalLimit = 0;
                $.totalApproved = 0;
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
            $.approvalLimit = limit;
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
        (bool isApproval, uint256 amount) = _isApproval(callData);
        if (!isApproval) return VALIDATION_FAILED;

        TokenPolicyData storage $ = _getPolicy({ id: id, userOpSender: account, token: target });

        // Increment the total approved amount
        $.totalApproved += amount;

        if ($.totalApproved > $.approvalLimit) {
            return VALIDATION_FAILED;
        }

        emit TokenApproved(id, msg.sender, target, account, amount, $.approvalLimit - $.totalApproved);
        return VALIDATION_SUCCESS;
    }

    /**
     * @notice Returns the limit and spent amount for a given token under permission, account, multiplexer.
     * @param id The config ID.
     * @param multiplexer The multiplexer address.
     * @param token The token address.
     * @param userOpSender The user operation sender address.
     * @return approvalLimit The spending limit.
     * @return totalApproved The already spent amount.
     */
    function getPolicyData(
        ConfigId id,
        address multiplexer,
        address token,
        address userOpSender
    )
        external
        view
        returns (uint256 approvalLimit, uint256 totalApproved)
    {
        if (token == address(0)) revert InvalidTokenAddress(token);
        if (!$tokens[id][multiplexer].contains(userOpSender, token)) {
            revert InvalidTokenAddress(token);
        }
        TokenPolicyData memory $ = $policyData[id][multiplexer][token][userOpSender];
        return ($.approvalLimit, $.totalApproved);
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
     * @notice Checks if the call is an approval.
     * @param callData The call data.
     * @dev returns bool => isApproval, amount of approval
     */
    function _isApproval(bytes calldata callData) internal pure returns (bool, uint256) {
        bytes4 functionSelector = bytes4(callData[0:4]);

        if (functionSelector == IERC20.approve.selector) {
            (, uint256 amount) = abi.decode(callData[4:], (address, uint256));
            return (true, amount);
        } else if (functionSelector == bytes4(keccak256("increaseAllowance(address,uint256)"))) {
            (, uint256 amount) = abi.decode(callData[4:], (address, uint256));
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
