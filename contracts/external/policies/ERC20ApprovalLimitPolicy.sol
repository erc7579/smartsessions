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
    error AlreadyApprovedForSpender(ConfigId id, address spender, address account);

    struct ApprovalConfig {
        mapping(address userOpSender => uint256 limit) limits;
        mapping(address spender => mapping(address userOpSender => uint256 alreadyApproved)) approved;
        EnumerableSet.AddressSet spenders;
        mapping(address userOpSender => uint256 totalApproved) totalApproved;
    }

    mapping(ConfigId id => mapping(address multiplexer => EnumerableSet.AddressSet tokensEnabled)) internal $tokens;
    mapping(ConfigId id => mapping(address multiplexer => mapping(address token => ApprovalConfig))) internal $policyData;

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
                ApprovalConfig storage $ = _getApprovalConfig({ id: configId, multiplexer: msg.sender, token: $t.at(account, i) });
                // clear limit
                $.limits[account] = 0;
                $.totalApproved[account] = 0;
                // clear approved
                uint256 len = $.spenders.length(account);
                for (uint256 j; j < len; j++) {
                    $.approved[$.spenders.at(account, j)][account] = 0;
                }
                $.spenders.removeAll(account);
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
            ApprovalConfig storage $ = _getApprovalConfig({ id: configId, multiplexer: msg.sender, token: token });
            // set limit
            $.limits[account] = limit;
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
        // no eth value allowed
        if (value != 0) return VALIDATION_FAILED;

        ApprovalConfig storage $ = _getApprovalConfig({ id: id, multiplexer: msg.sender, token: target });

        bytes4 functionSelector = bytes4(callData[0:4]);
        address spender;
        uint256 amount;

        if (functionSelector == IERC20.approve.selector) {
            (spender, amount) = abi.decode(callData[4:], (address, uint256));
            if ($.approved[spender][account] > 0) {
                revert AlreadyApprovedForSpender(id, spender, account);
            }
        } else if (functionSelector == bytes4(keccak256("increaseAllowance(address,uint256)"))) {
            (spender, amount) = abi.decode(callData[4:], (address, uint256));
        } else {
            return VALIDATION_FAILED;
        }

        uint256 _totalApproved = $.totalApproved[account] + amount;
        uint256 _limit = $.limits[account];
        if (_totalApproved > _limit) {
            return VALIDATION_FAILED;
        }
        
        // Increment the total approved amount
        $.totalApproved[account] += amount;
        $.approved[spender][account] = amount;
        $.spenders.add(account, spender);

        emit TokenApproved(id, msg.sender, target, account, amount, _limit - _totalApproved); 
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
        ApprovalConfig storage $ = _getApprovalConfig({ id: id, multiplexer: multiplexer, token: token });
        return ($.limits[userOpSender], $.totalApproved[userOpSender]);
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

    function _getApprovalConfig(
        ConfigId id,
        address multiplexer,
        address token
    )
        internal
        view
        returns (ApprovalConfig storage s)
    {
        if (token == address(0)) revert InvalidTokenAddress(token);
        s = $policyData[id][multiplexer][token];
    }
}
