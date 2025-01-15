// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "../../DataTypes.sol";
import {
    IActionPolicy,
    I1271Policy,
    IUserOpPolicy,
    IPolicy,
    VALIDATION_SUCCESS,
    VALIDATION_FAILED
} from "../../interfaces/IPolicy.sol";
import { PackedUserOperation, _packValidationData } from "@rhinestone/modulekit/src/external/ERC4337.sol";
import { IERC165 } from "forge-std/interfaces/IERC165.sol";

import "forge-std/console2.sol";

type TimeFrameConfig is uint256;

/**
 * @title TimeFramePolicy
 * @notice This policy checks if current block timestamp is within a valid time frame.
 * It is used to limit the time frame of an action / user operation.
 * It packs the valid time frame into validation data to be returned to the EntryPoint.
 */
contract TimeFramePolicy is IPolicy, IUserOpPolicy, IActionPolicy, I1271Policy {
    using TimeFrameConfigLib for TimeFrameConfig;

    mapping(ConfigId id => mapping(address msgSender => mapping(address opSender => TimeFrameConfig))) public
        timeFrameConfigs;

    /**
     * @notice Checks if the user operation is within the valid time frame.
     * @param id The config ID.
     * @param op The user operation.
     */
    function checkUserOpPolicy(ConfigId id, PackedUserOperation calldata op) external view override returns (uint256) {
        return _checkTimeFrame(id, msg.sender, op.sender);
    }

    /**
     * @notice Checks if the action is within the valid time frame.
     * @param id The config ID.
     * @param account The account.
     */
    function checkAction(
        ConfigId id,
        address account,
        address,
        uint256,
        bytes calldata
    )
        external
        view
        returns (uint256)
    {
        return _checkTimeFrame(id, msg.sender, account);
    }

    /**
     * @notice Checks if the 1271 signed action is within the valid time frame.
     * @param id The config ID.
     * @param smartAccount The account.
     */
    function check1271SignedAction(
        ConfigId id,
        address,
        address smartAccount,
        bytes32,
        bytes calldata
    )
        external
        view
        returns (bool)
    {
        TimeFrameConfig config = timeFrameConfigs[id][msg.sender][smartAccount];

        require(
            config.validUntil() != 0 || config.validAfter() != 0, PolicyNotInitialized(id, msg.sender, smartAccount)
        );
        if (
            (block.timestamp < config.validUntil() || config.validUntil() == 0)
                && block.timestamp >= config.validAfter()
        ) {
            return true;
        }
        return false;
    }

    function _checkTimeFrame(ConfigId id, address multiplexer, address smartAccount) internal view returns (uint256) {
        TimeFrameConfig config = timeFrameConfigs[id][multiplexer][smartAccount];
        require(
            config.validUntil() != 0 || config.validAfter() != 0, PolicyNotInitialized(id, multiplexer, smartAccount)
        );
        return
            _packValidationData({ sigFailed: false, validUntil: config.validUntil(), validAfter: config.validAfter() });
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
        timeFrameConfigs[configId][msg.sender][account] = TimeFrameConfig.wrap(uint256(uint96(bytes12(initData[0:12]))));
        emit IPolicy.PolicySet(configId, msg.sender, account);
    }

    /**
     * @notice Returns the time frame config.
     * @param id The config ID.
     * @param multiplexer The multiplexer.
     * @param smartAccount The smart account.
     * @return The time frame config.
     */
    function getTimeFrameConfig(
        ConfigId id,
        address multiplexer,
        address smartAccount
    )
        external
        view
        returns (TimeFrameConfig)
    {
        return timeFrameConfigs[id][multiplexer][smartAccount];
    }

    /**
     * @notice Returns true if the interface is supported, false otherwise.
     * @param interfaceID The interface ID.
     * @return True if the interface is supported, false otherwise.
     */
    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return (
            interfaceID == type(IERC165).interfaceId || interfaceID == type(IPolicy).interfaceId
                || interfaceID == type(IActionPolicy).interfaceId || interfaceID == type(I1271Policy).interfaceId
                || interfaceID == type(IUserOpPolicy).interfaceId
        );
    }
}

library TimeFrameConfigLib {
    function validUntil(TimeFrameConfig config) internal pure returns (uint48) {
        return uint48(TimeFrameConfig.unwrap(config) >> 48);
    }

    function validAfter(TimeFrameConfig config) internal pure returns (uint48) {
        return uint48(TimeFrameConfig.unwrap(config));
    }
}
