// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "../../DataTypes.sol";
import { IActionPolicy, IPolicy, VALIDATION_SUCCESS, VALIDATION_FAILED } from "../../interfaces/IPolicy.sol";
import { EnumerableSet } from "../../utils/EnumerableSet4337.sol";
import { IERC165 } from "forge-std/interfaces/IERC165.sol";

/**
 * @title ContractWhitelistPolicy | ActionPolicy
 * @notice This policy checks if the target is whitelisted.
 *         Should be used as a fallback action policy.
 */
contract ContractWhitelistPolicy is IPolicy, IActionPolicy {
    error InvalidInitData();

    using EnumerableSet for EnumerableSet.AddressSet;

    mapping(ConfigId id => mapping(address msgSender => EnumerableSet.AddressSet targets)) internal whitelistedTargets;

    /**
     * @notice Checks if the action is within the valid time frame.
     * @param id The config ID.
     * @param account The account.
     */
    function checkAction(
        ConfigId id,
        address account,
        address target,
        uint256,
        bytes calldata
    )
        external
        view
        returns (uint256)
    {
        if (whitelistedTargets[id][msg.sender].contains(account, target)) {
            return VALIDATION_SUCCESS;
        }
        return VALIDATION_FAILED;
    }

    /**
     * @notice Initializes the policy.
     * Overwrites state.
     * @notice ATTENTION: This method is called during permission installation as part of the enabling policies flow.
     * A secure policy would minimize external calls from this method (ideally, to 0) to prevent passing control flow to
     * external contracts.
     * @param account The account.
     * @param configId The config ID.
     * @param initData The initialization data.
     */
    function initializeWithMultiplexer(address account, ConfigId configId, bytes calldata initData) external {
        EnumerableSet.AddressSet storage $targets = whitelistedTargets[configId][msg.sender];
        require(initData.length % 20 == 0 && initData.length > 0, InvalidInitData());
        uint256 targetsLength = initData.length / 20;
        for (uint256 i = 0; i < targetsLength; i++) {
            address target;
            assembly {
                target := shr(96, calldataload(add(initData.offset, mul(i, 0x14))))
            }
            require(target != address(0), InvalidInitData());
            $targets.add(account, target);
        }
        emit IPolicy.PolicySet(configId, msg.sender, account);
    }

    /**
     * @notice Returns the time frame config.
     * @param id The config ID.
     * @param multiplexer The multiplexer.
     * @param smartAccount The smart account.
     * @return The time frame config.
     */
    function isContractWhitelisted(
        ConfigId id,
        address multiplexer,
        address smartAccount,
        address target
    )
        external
        view
        returns (bool)
    {
        return whitelistedTargets[id][multiplexer].contains(smartAccount, target);
    }

    /**
     * @notice Returns true if the interface is supported, false otherwise.
     * @param interfaceID The interface ID.
     * @return True if the interface is supported, false otherwise.
     */
    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return (
            interfaceID == type(IERC165).interfaceId || interfaceID == type(IPolicy).interfaceId
                || interfaceID == type(IActionPolicy).interfaceId
        );
    }
}
