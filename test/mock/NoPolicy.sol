// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "contracts/interfaces/IPolicy.sol";
import { _packValidationData } from "@ERC4337/account-abstraction/contracts/core/Helpers.sol";

contract NoPolicy is IActionPolicy {
    mapping(ConfigId id => mapping(address msgSender => mapping(address userOpSender => uint256 calls))) public
        actionState;

    function initializeWithMultiplexer(address account, ConfigId configId, bytes calldata initData) external {
        actionState[configId][msg.sender][account] = 1;
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
        return 1; // sig validation failed
    }

    function supportsInterface(bytes4 interfaceID) external view override returns (bool) {
        return interfaceID == type(IPolicy).interfaceId || interfaceID == type(IUserOpPolicy).interfaceId
            || interfaceID == type(IActionPolicy).interfaceId || interfaceID == type(I1271Policy).interfaceId
            || interfaceID == type(IERC165).interfaceId;
    }
}
