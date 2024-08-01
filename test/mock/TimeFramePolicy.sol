// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "contracts/interfaces/IPolicy.sol";
import "contracts/lib/SubLib.sol";

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

    using SubLib for bytes;

    mapping(address msgSender => mapping(address opSender => uint256)) public usedIds;
    mapping(SessionId id => mapping(address msgSender => mapping(address opSender => Status))) public status;
    mapping(SessionId id => mapping(address msgSender => mapping(address opSender => TimeFrameConfig))) public
        timeFrameConfigs;

    function checkUserOpPolicy(
        SessionId id,
        PackedUserOperation calldata op
    )
        external
        view
        override
        returns (uint256)
    {
        return _checkTimeFrame(id, msg.sender, op.sender);
    }

    function checkAction(
        SessionId id,
        address,
        uint256,
        bytes calldata,
        PackedUserOperation calldata op
    )
        external
        view
        returns (uint256)
    {
        return _checkTimeFrame(id, msg.sender, op.sender);
    }

    /*
    function check1271SignedAction(
        bytes32 id,
        address smartAccount,
        address,
        bytes32,
        bytes calldata
    )
        external
        view
        returns (bool)
    {
        require(status[id][smartAccount] == Status.Live);
        TimeFrameConfig storage config = timeFrameConfigs[id][smartAccount];
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
    */

    function _checkTimeFrame(SessionId id, address multiplexer, address smartAccount) internal view returns (uint256) {
        require(status[id][multiplexer][smartAccount] == Status.Live);
        TimeFrameConfig storage config = timeFrameConfigs[id][multiplexer][smartAccount];
        return _packValidationData(false, config.validUntil, config.validAfter);
    }

    function _onInstallPolicy(SessionId id, address opSender, bytes calldata _data) internal {
        require(status[id][msg.sender][opSender] == Status.NA);
        usedIds[msg.sender][opSender]++;
        status[id][msg.sender][opSender] = Status.Live;
        timeFrameConfigs[id][msg.sender][opSender].validUntil = uint48(uint128(bytes16(_data[0:16])));
        timeFrameConfigs[id][msg.sender][opSender].validAfter = uint48(uint128(bytes16(_data[16:32])));
    }

    function _onUninstallPolicy(SessionId id, address opSender, bytes calldata) internal {
        require(status[id][msg.sender][opSender] == Status.Live);
        status[id][msg.sender][opSender] = Status.Deprecated;
        usedIds[msg.sender][opSender]--;
    }

    function onInstall(bytes calldata data) external {
        (SessionId id, address opSender, bytes calldata _data) = data.parseInstallData();
        _onInstallPolicy(id, opSender, _data);
    }

    function onUninstall(bytes calldata data) external {
        (SessionId id, address opSender, bytes calldata _data) = data.parseInstallData();
        _onUninstallPolicy(id, opSender, _data);
    }

    function isModuleType(uint256 id) external pure returns (bool) {
        return id == 7;
    }

    function isInitialized(address smartAccount) external view returns (bool) {
        return usedIds[msg.sender][smartAccount] > 0;
    }

    function isInitialized(address multiplexer, address smartAccount) external view returns (bool) {
        return usedIds[multiplexer][smartAccount] > 0;
    }

    function isInitialized(address account, SessionId id) external view override returns (bool) {
        return status[id][msg.sender][account] == Status.Live;
    }

    function isInitialized(address multiplexer, address account, SessionId id) external view override returns (bool) {
        return status[id][multiplexer][account] == Status.Live;
    }

    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return true;
    }
}
