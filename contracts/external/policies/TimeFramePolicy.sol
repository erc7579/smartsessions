// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "../../DataTypes.sol";
import { IActionPolicy, I1271Policy, IUserOpPolicy, IPolicy, VALIDATION_SUCCESS, VALIDATION_FAILED } from "../../interfaces/IPolicy.sol";
import { PackedUserOperation, _packValidationData } from "@rhinestone/modulekit/src/external/ERC4337.sol";
import { IERC165 } from "forge-std/interfaces/IERC165.sol";

import "forge-std/console2.sol";

contract TimeFramePolicy is IPolicy, IUserOpPolicy, IActionPolicy, I1271Policy {
    
    error PolicyNotInitialized(ConfigId id, address mxer, address account);

    struct TimeFrameConfig {
        uint48 validUntil;
        uint48 validAfter;
    }

    enum Status {
        NA,
        Live,
        Deprecated
    }

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
        TimeFrameConfig storage $config = timeFrameConfigs[id][msg.sender][smartAccount];
        uint256 validUntil = $config.validUntil;
        uint256 validAfter = $config.validAfter;
        require(validUntil != 0 || validAfter != 0, PolicyNotInitialized(id, msg.sender, smartAccount));
        if ((block.timestamp < validUntil || validUntil == 0) && block.timestamp >= validAfter) {
            return true;
        }
        return false;
    }

    function _checkTimeFrame(ConfigId id, address multiplexer, address smartAccount) internal view returns (uint256) {
        TimeFrameConfig storage $config = timeFrameConfigs[id][multiplexer][smartAccount];
        uint48 validUntil = $config.validUntil;
        uint48 validAfter = $config.validAfter;
        require(validUntil != 0 || validAfter != 0, PolicyNotInitialized(id, msg.sender, smartAccount));
        return _packValidationData({sigFailed:false, validUntil: validUntil, validAfter: validAfter});
    }

    function initializeWithMultiplexer(address account, ConfigId configId, bytes calldata initData) external {
        timeFrameConfigs[configId][msg.sender][account].validUntil = uint48(uint128(bytes16(initData[0:16])));
        timeFrameConfigs[configId][msg.sender][account].validAfter = uint48(uint128(bytes16(initData[16:32])));
    }
    
    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return (
            interfaceID == type(IERC165).interfaceId || interfaceID == type(IPolicy).interfaceId
                || interfaceID == type(IActionPolicy).interfaceId || interfaceID == type(I1271Policy).interfaceId
                || interfaceID == type(IUserOpPolicy).interfaceId
        );
    }
}