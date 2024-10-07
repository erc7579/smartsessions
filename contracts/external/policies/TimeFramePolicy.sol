// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "../../DataTypes.sol";
import { IActionPolicy, I1271Policy, IUserOpPolicy, IPolicy, VALIDATION_SUCCESS, VALIDATION_FAILED } from "../../interfaces/IPolicy.sol";
import { PackedUserOperation, _packValidationData } from "@rhinestone/modulekit/src/external/ERC4337.sol";
import { IERC165 } from "forge-std/interfaces/IERC165.sol";

struct TimeFrameConfig {
    uint48 validUntil;
    uint48 validAfter;
}

contract TimeFramePolicy is IPolicy, IUserOpPolicy, IActionPolicy, I1271Policy {

    mapping(ConfigId id => mapping(address msgSender => mapping(address opSender => TimeFrameConfig))) public
        timeFrameConfigs;

    function checkUserOpPolicy(ConfigId id, PackedUserOperation calldata op) external view override returns (uint256) {
        return _checkTimeFrame(id, msg.sender, op.sender);
    }

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
        TimeFrameConfig memory config = timeFrameConfigs[id][msg.sender][smartAccount];
        require(config.validUntil != 0 || config.validAfter != 0, PolicyNotInitialized(id, msg.sender, smartAccount));
        if ((block.timestamp < config.validUntil || config.validUntil == 0) && block.timestamp >= config.validAfter) {
            return true;
        }
        return false;
    }

    function _checkTimeFrame(ConfigId id, address multiplexer, address smartAccount) internal view returns (uint256) {
        TimeFrameConfig memory config = timeFrameConfigs[id][multiplexer][smartAccount];
        require(config.validUntil != 0 || config.validAfter != 0, PolicyNotInitialized(id, multiplexer, smartAccount));
        return _packValidationData({sigFailed:false, validUntil: config.validUntil, validAfter: config.validAfter});
    }

    function initializeWithMultiplexer(address account, ConfigId configId, bytes calldata initData) external {
        timeFrameConfigs[configId][msg.sender][account].validUntil = uint48(uint128(bytes16(initData[0:16])));
        timeFrameConfigs[configId][msg.sender][account].validAfter = uint48(uint128(bytes16(initData[16:32])));
    }

    function getTimeFrameConfig(ConfigId id, address multiplexer, address smartAccount) external view returns (TimeFrameConfig memory) {
        return timeFrameConfigs[id][multiplexer][smartAccount];
    }
    
    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return (
            interfaceID == type(IERC165).interfaceId || interfaceID == type(IPolicy).interfaceId
                || interfaceID == type(IActionPolicy).interfaceId || interfaceID == type(I1271Policy).interfaceId
                || interfaceID == type(IUserOpPolicy).interfaceId
        );
    }
}