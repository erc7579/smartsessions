// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "contracts/interfaces/IPolicy.sol";
import "contracts/DataTypes.sol";
import "forge-std/console2.sol";

contract YesPolicy is IUserOpPolicy, IActionPolicy, I1271Policy {

    mapping(ConfigId id => mapping(address msgSender => mapping(address userOpSender => uint256 calls))) public
        userOpState;

    mapping(ConfigId id => mapping(address msgSender => mapping(address userOpSender => uint256 calls))) public
        actionState;

    function initializeWithMultiplexer(address account, ConfigId configId, bytes calldata initData) external {
        userOpState[configId][msg.sender][account] = 1;
    }

    function checkUserOpPolicy(ConfigId id, PackedUserOperation calldata userOp) external override returns (uint256) {
        userOpState[id][msg.sender][userOp.sender] += 1;
        return 0;
    }

    function checkAction(
        ConfigId id,
        address account,
        address target,
        uint256 value,
        bytes calldata data
    )
        external
        override
        returns (uint256)
    {
        actionState[id][msg.sender][account] += 1;
    }

    function supportsInterface(bytes4 interfaceID) external view override returns (bool) {
        return true;
    }

    function check1271SignedAction(
        ConfigId id,
        address requestSender,
        address account,
        bytes32 hash,
        bytes calldata signature
    )
        external
        view
        returns (bool)
    {
        return true;
    }
}
