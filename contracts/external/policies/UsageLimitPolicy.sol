// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "contracts/interfaces/IPolicy.sol";
import "contracts/lib/SubModuleLib.sol";

contract UsageLimitPolicy is IUserOpPolicy, IActionPolicy {

    error UsageLimitExceeded(uint128 used, uint128 limit);

    struct UsageLimitConfig {
        uint128 limit;
        uint128 used;
    }

    using SubModuleLib for bytes;

    mapping(ConfigId id => mapping(address msgSender => mapping(address userOpSender => UsageLimitConfig))) public
        usageLimitConfigs;

    function checkUserOpPolicy(ConfigId id, PackedUserOperation calldata op) external returns (uint256) {
        return _checkUsageLimit(id, msg.sender, op.sender);
    }

    function checkAction(ConfigId id, address account, address, uint256, bytes calldata) external returns (uint256) {
        return _checkUsageLimit(id, msg.sender, account);
    }

    function _checkUsageLimit(ConfigId id, address mxer, address smartAccount) internal returns (uint256) {
        UsageLimitConfig storage $config = usageLimitConfigs[id][mxer][smartAccount];
        uint128 limit = $config.limit;
        require(limit > 0, PolicyNotInitialized(id, mxer, smartAccount));
        if (++$config.used > limit) {
            revert UsageLimitExceeded($config.used, limit);
        }
        return VALIDATION_SUCCESS;
    }

    function initializeWithMultiplexer(address account, ConfigId configId, bytes calldata initData) external {
        usageLimitConfigs[configId][msg.sender][account].limit = uint128(bytes16(initData[0:16]));
        usageLimitConfigs[configId][msg.sender][account].used = 0;
    }

    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return interfaceID == type(IERC165).interfaceId || interfaceID == type(IPolicy).interfaceId
            || interfaceID == type(IUserOpPolicy).interfaceId || interfaceID == type(IActionPolicy).interfaceId;
    }
}
