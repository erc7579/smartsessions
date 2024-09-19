// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "contracts/interfaces/IPolicy.sol";
import "contracts/lib/SubModuleLib.sol";

import "forge-std/console2.sol";

contract TimeFramePolicy is IUserOpPolicy, IActionPolicy {
    struct TimeFrameConfig {
        uint48 validUntil;
        uint48 validAfter;
    }

    enum Status {
        NA,
        Live,
        Deprecated
    }

    using SubModuleLib for bytes;

    mapping(address msgSender => mapping(address opSender => uint256)) public usedIds;
    mapping(ConfigId id => mapping(address msgSender => mapping(address opSender => Status))) public status;
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
        require(status[id][msg.sender][smartAccount] == Status.Live);
        TimeFrameConfig storage config = timeFrameConfigs[id][msg.sender][smartAccount];
        if (config.validUntil == 0 && config.validAfter == 0) {
            revert("TimeFramePolicy: policy not installed");
        }
        uint256 validUntil = config.validUntil;
        uint256 validAfter = config.validAfter;
        if ((block.timestamp < validUntil || validUntil == 0) && block.timestamp > validAfter) {
            return true;
        }
        return false;
    }

    function _checkTimeFrame(ConfigId id, address multiplexer, address smartAccount) internal view returns (uint256) {
        require(status[id][multiplexer][smartAccount] == Status.Live);
        TimeFrameConfig storage config = timeFrameConfigs[id][multiplexer][smartAccount];
        return _packValidationData(false, config.validUntil, config.validAfter);
    }

    function _onInstallPolicy(ConfigId id, address mxer, address opSender, bytes calldata _data) internal {
        usedIds[mxer][opSender]++;
        status[id][mxer][opSender] = Status.Live;
        timeFrameConfigs[id][mxer][opSender].validUntil = uint48(uint128(bytes16(_data[0:16])));
        timeFrameConfigs[id][mxer][opSender].validAfter = uint48(uint128(bytes16(_data[16:32])));
    }

    function _onUninstallPolicy(ConfigId id, address mxer, address opSender, bytes calldata) internal {
        status[id][mxer][opSender] = Status.Deprecated;
        usedIds[mxer][opSender]--;
    }

    function onInstall(bytes calldata data) external {
        (ConfigId id, bytes calldata _data) = data.parseInstallData();
        require(status[id][msg.sender][msg.sender] == Status.NA);
        _onInstallPolicy(id, msg.sender, msg.sender, _data);
    }

    function initializeWithMultiplexer(address account, ConfigId configId, bytes calldata initData) external {
        _onInstallPolicy(configId, msg.sender, account, initData);
    }

    function onUninstall(bytes calldata data) external {
        (ConfigId id, bytes calldata _data) = data.parseInstallData();
        require(status[id][msg.sender][msg.sender] == Status.Live);
        _onUninstallPolicy(id, msg.sender, msg.sender, _data);
    }

    function isModuleType(uint256 id) external pure returns (bool) {
        return id == 7;
    }

    function isInitialized(address smartAccount) external view returns (bool) {
        return usedIds[msg.sender][smartAccount] > 0;
    }

    // function isInitialized(address account, address multiplexer, ConfigId id) external view override returns (bool) {
    //     return status[id][multiplexer][account] == Status.Live;
    // }

    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return true;
    }
}
