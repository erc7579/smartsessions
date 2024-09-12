// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "../../interfaces/IPolicy.sol";
import "../../lib/SubModuleLib.sol";
import "../../utils/EnumerableSet4337.sol";

contract YesPolicy is IUserOpPolicy, IActionPolicy, I1271Policy {
    using EnumerableSet for EnumerableSet.Bytes32Set;

    event SudoPolicyInstalledMultiplexer(address indexed account, address indexed multiplexer, ConfigId indexed id);
    event SudoPolicyUninstalledAllAccount(address indexed account);
    event SudoPolicySet(address indexed account, address indexed multiplexer, ConfigId indexed id);

    mapping(address account => bool isInitialized) internal $initialized;
    mapping(address multiplexer => EnumerableSet.Bytes32Set configIds) internal $enabledConfigs;

    function onInstall(bytes calldata data) external {
        bool _isInitialized = isInitialized(msg.sender);
        if (_isInitialized) revert AlreadyInitialized(msg.sender);
        $initialized[msg.sender] = true;
        if (data.length == 0) return;
        ConfigId[] memory configs = abi.decode(data, (ConfigId[]));
        uint256 length = configs.length;
        for (uint256 i; i < length; i++) {
            $enabledConfigs[msg.sender].add(msg.sender, ConfigId.unwrap(configs[i]));
            emit SudoPolicySet(msg.sender, msg.sender, configs[i]);
        }
    }

    function initializeWithMultiplexer(address account, ConfigId configId, bytes calldata /*initData*/ ) external {
        $enabledConfigs[msg.sender].add(account, ConfigId.unwrap(configId));
        emit SudoPolicySet(msg.sender, account, configId);
    }

    function onUninstall(bytes calldata /*data*/ ) external {
        EnumerableSet.Bytes32Set storage configIds = $enabledConfigs[msg.sender];
        configIds.removeAll(msg.sender);
        $initialized[msg.sender] = false;
        emit SudoPolicyUninstalledAllAccount(msg.sender);
    }

    function isModuleType(uint256 id) external pure returns (bool) {
        return id == ERC7579_MODULE_TYPE_POLICY;
    }

    function checkUserOpPolicy(
        ConfigId, /*id*/
        PackedUserOperation calldata /*userOp*/
    )
        external
        pure
        override
        returns (uint256)
    {
        return 0;
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
        return 0;
    }

    function isInitialized(address account, ConfigId id) external view override returns (bool) {
        return $enabledConfigs[account].contains(account, ConfigId.unwrap(id));
    }

    function isInitialized(address account, address multiplexer, ConfigId id) external view override returns (bool) {
        return $enabledConfigs[multiplexer].contains(account, ConfigId.unwrap(id));
    }

    function isInitialized(address account) public view override returns (bool) {
        return $initialized[account];
    }

    function supportsInterface(bytes4 /*interfaceID*/ ) external pure override returns (bool) {
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
