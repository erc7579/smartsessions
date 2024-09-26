// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "../../interfaces/IPolicy.sol";
import "../../lib/SubModuleLib.sol";
import "../../utils/EnumerableSet4337.sol";
import { IERC165 } from "forge-std/interfaces/IERC165.sol";

contract SudoPolicy is IActionPolicy, I1271Policy {
    using EnumerableSet for EnumerableSet.Bytes32Set;

    event SudoPolicyInstalledMultiplexer(address indexed account, address indexed multiplexer, ConfigId indexed id);
    event SudoPolicyUninstalledAllAccount(address indexed account);
    event SudoPolicySet(address indexed account, address indexed multiplexer, ConfigId indexed id);
    event SudoPolicyRemoved(address indexed account, address indexed multiplexer, ConfigId indexed id);

    mapping(address account => bool isInitialized) internal $initialized;
    mapping(address multiplexer => EnumerableSet.Bytes32Set configIds) internal $enabledConfigs;

    // to be used if policy installed through multiplexer such as Smart Sessions Module
    function initializeWithMultiplexer(address account, ConfigId configId, bytes calldata /*initData*/ ) external {
        $enabledConfigs[msg.sender].add(account, ConfigId.unwrap(configId));
        emit IPolicy.PolicySet(configId, msg.sender, account);
    }

    function checkAction(
        ConfigId, /*id*/
        address, /*account*/
        address, /*target*/
        uint256, /*value*/
        bytes calldata /*data*/
    )
        external
        pure
        override
        returns (uint256)
    {
        return VALIDATION_SUCCESS;
    }

    function check1271SignedAction(
        ConfigId id,
        address requestSender,
        address account,
        bytes32 hash,
        bytes calldata signature
    )
        external
        pure
        returns (bool)
    {
        return true;
    }

    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return interfaceID == type(IActionPolicy).interfaceId || interfaceID == type(I1271Policy).interfaceId
            || interfaceID == IActionPolicy.checkAction.selector || interfaceID == type(IERC165).interfaceId
            || interfaceID == I1271Policy.check1271SignedAction.selector;
    }
}
