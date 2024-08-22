// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.4;

import "./DataTypes.sol";

interface ISmartSession {
    error AssociatedArray_OutOfBounds(uint256 index);
    error ChainIdMismatch(uint64 providedChainId);
    error HashIndexOutOfBounds(uint256 index);
    error HashMismatch(bytes32 providedHash, bytes32 computedHash);
    error InvalidData();
    error InvalidEnableSignature(address account, bytes32 hash);
    error InvalidISigner(ISigner isigner);
    error InvalidSelfCall();
    error InvalidSession(SignerId signerId);
    error InvalidSessionKeySignature(SignerId signerId, address isigner, address account, bytes32 userOpHash);
    error InvalidSignerId(SignerId signerId);
    error InvalidUserOpSender(address sender);
    error NoPoliciesSet(SignerId signerId);
    error PartlyEnabledActions();
    error PartlyEnabledPolicies();
    error PermissionPartlyEnabled();
    error PolicyViolation(SignerId signerId, address policy);
    error SignerNotFound(SignerId signerId, address account);
    error UnsupportedExecutionType();
    error UnsupportedPolicy(address policy);
    error UnsupportedSmartSessionMode(SmartSessionMode mode);

    event IterNonce(SignerId signerId, address account, uint256 newValue);
    event PolicyDisabled(SignerId signerId, PolicyType policyType, address policy, address smartAccount);
    event PolicyEnabled(SignerId signerId, PolicyType policyType, address policy, address smartAccount);
    event SessionCreated(SignerId signerId, address account);
    event SessionRemoved(SignerId signerId, address smartAccount);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           ERC7579                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function validateUserOp(
        PackedUserOperation memory userOp,
        bytes32 userOpHash
    )
        external
        returns (ValidationData vd);
    function onInstall(bytes memory data) external;
    function onUninstall(bytes memory) external;

    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes memory signature
    )
        external
        view
        returns (bytes4 result);

    function isInitialized(address smartAccount) external view returns (bool);
    function isModuleType(uint256 typeID) external pure returns (bool);
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      Manage Sessions                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
    function enableActionPolicies(SignerId signerId, ActionData[] memory actionPolicies) external;
    function enableERC1271Policies(SignerId signerId, PolicyData[] memory erc1271Policies) external;
    function enableSessions(Session[] memory sessions) external returns (SignerId[] memory signerIds);
    function enableUserOpPolicies(SignerId signerId, PolicyData[] memory userOpPolicies) external;
    function disableActionPolicies(SignerId signerId, ActionId actionId, address[] memory policies) external;
    function disableERC1271Policies(SignerId signerId, address[] memory policies) external;
    function disableUserOpPolicies(SignerId signerId, address[] memory policies) external;

    function removeSession(SignerId signerId) external;
    function revokeEnableSignature(SignerId signerId) external;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      View Functions                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function getDigest(
        SignerId signerId,
        address account,
        Session memory data,
        SmartSessionMode mode
    )
        external
        view
        returns (bytes32);

    function getNonce(SignerId signerId, address account) external view returns (uint256);
    function getSignerId(Session memory session) external pure returns (SignerId signerId);
    function isPermissionEnabled(
        SignerId signerId,
        address account,
        PolicyData[] memory userOpPolicies,
        PolicyData[] memory erc1271Policies,
        ActionData[] memory actions
    )
        external
        view
        returns (bool isEnabled);
    function isSessionEnabled(SignerId signerId, address account) external view returns (bool);
    function supportsNestedTypedDataSign() external view returns (bytes32 result);
}
