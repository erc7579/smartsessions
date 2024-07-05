// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.4;

import "./DataTypes.sol";
import { ERC7579ValidatorBase } from "modulekit/Modules.sol";

interface ISmartSession {
    error AlreadyInitialized(address smartAccount);
    error ExecuteUserOpIsNotSupported();
    error InvalidEnableSignature(address account, bytes32 hash);
    error InvalidISigner(ISigner isigner);
    error InvalidSessionKeySignature(SignerId signerId, address isigner, address account, bytes32 userOpHash);
    error NoPoliciesSet(SignerId signerId);
    error NotInitialized(address smartAccount);
    error PolicyViolation(SignerId signerId, address policy);
    error SignerNotFound(SignerId signerId, address account);
    error UnsupportedPolicy(address policy);

    event PolicyEnabled(SignerId signerId, address policy, address smartAccount);
    event SessionRemoved(SignerId signerId, address smartAccount);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     Manage Sessions                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
    function enableActionPolicies(SignerId signerId, ActionData[] memory actionPolicies) external;
    function enableERC1271Policies(SignerId signerId, PolicyData[] memory erc1271Policies) external;
    function enableSessions(InstallSessions[] memory sessions) external;
    function enableUserOpPolicies(SignerId signerId, PolicyData[] memory userOpPolicies) external;
    function removeSession(SignerId signerId) external;
    function setSigner(SignerId signerId, address signer, bytes memory initData) external;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     ERC7579 Functions                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
    function onInstall(bytes memory data) external;
    function onUninstall(bytes memory data) external;
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        external
        returns (ERC7579ValidatorBase.ValidationData vd);

    function isInitialized(address smartAccount) external view returns (bool);
    function isModuleType(uint256 typeID) external pure returns (bool);
    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata signature
    )
        external
        view
        returns (bytes4 sigValidationResult);
}
