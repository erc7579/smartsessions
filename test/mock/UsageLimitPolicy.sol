// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "contracts/interfaces/IPolicy.sol";
import "contracts/lib/SubLib.sol";

contract UsageLimitPolicy is IUserOpPolicy, IActionPolicy {
    enum Status {
        NA,
        Live,
        Deprecated
    }

    struct UsageLimitConfig {
        uint256 limit;
        uint256 used;
    }

    using SubLib for bytes;

    mapping(address msgSender => mapping(address opSender => uint256)) public usedIds;
    mapping(SessionId id => mapping(address msgSender => mapping(address userOpSender => Status))) public status;
    mapping(SessionId id => mapping(address msgSender => mapping(address userOpSender => UsageLimitConfig))) public
        usageLimitConfigs;

    function checkUserOpPolicy(SessionId id, PackedUserOperation calldata op) external returns (uint256) {
        return _checkUsageLimit(id, msg.sender, op.sender);
    }

    function checkAction(
        SessionId id,
        address,
        uint256,
        bytes calldata,
        PackedUserOperation calldata op
    )
        external
        returns (uint256)
    {
        return _checkUsageLimit(id, msg.sender, op.sender);
    }

    function _checkUsageLimit(SessionId id, address mxer, address smartAccount) internal returns (uint256) {
        require(status[id][mxer][smartAccount] == Status.Live);
        UsageLimitConfig storage config = usageLimitConfigs[id][mxer][smartAccount];
        if (config.limit == 0) {
            revert("UsageLimitPolicy: policy not installed");
        }
        if (++config.used > config.limit) {
            revert("UsageLimitPolicy: usage limit exceeded");
        }
        return VALIDATION_SUCCESS;
    }

    function _onInstallPolicy(SessionId id, address opSender, bytes calldata _data) internal {
        require(status[id][msg.sender][opSender] == Status.NA);
        usedIds[msg.sender][opSender]++;
        status[id][msg.sender][opSender] = Status.Live;
        usageLimitConfigs[id][msg.sender][opSender].limit = uint256(bytes32(_data[0:32]));
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

    function isInitialized(address account) external view returns (bool) {
        return usedIds[msg.sender][account] > 0;
    }

    function isInitialized(address mxer, address account) external view returns (bool) {
        return usedIds[mxer][account] > 0;
    }

    function isInitialized(address account, SessionId id) external view returns (bool) {
        return status[id][msg.sender][account] == Status.Live;
    }

    function isInitialized(address mxer, address account, SessionId id) external view returns (bool) {
        return status[id][mxer][account] == Status.Live;
    }

    function isModuleType(uint256 id) external pure returns (bool) {
        return id == 7;
    }

    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return true;
    }
}
