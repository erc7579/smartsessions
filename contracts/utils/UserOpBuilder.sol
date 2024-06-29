// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { IUserOperationBuilder, PackedUserOperation, Execution } from "contracts/utils/interfaces/IUserOpBuilder.sol";
import { IEntryPoint } from "modulekit/external/ERC4337.sol";
import { Exec } from "account-abstraction/utils/Exec.sol";
import { IERC7579Account } from "contracts/utils/interfaces/IERC7579Account.sol";
import { 
    ModeLib, 
    ExecutionMode, 
    ExecType, 
    CallType, 
    CALLTYPE_BATCH, 
    CALLTYPE_SINGLE, 
    CALLTYPE_STATIC, 
    CALLTYPE_DELEGATECALL
} from "contracts/utils/lib/ModeLib.sol";
import { ExecutionLib } from "erc7579/lib/ExecutionLib.sol";
import { IPermissionEnabled } from "contracts/validators/PermissionManager.sol";

import "forge-std/Console2.sol";

/*
   TODO: what if at the time of permission creation, even the permission module is
   not yet enabled for the SA? => Enable Mode!
   */

contract UserOperationBuilder is IUserOperationBuilder {
    /**
     *    PermissionContext is a bytes array with abi.encodePacked:
     *    1. Nonce key (24 bytes = 20 bytes validator address + 4 bytes key)
          2. ExecutionMode as per ERC-7579 (32 bytes)
     *    2. PermissionData as per the Std7579PermissionsModule:
     *         bytes1 enableModeFlag
     *         uint256 permissionIndex,
     *         uint48 validUntil,
     *         uint48 validAfter,
     *         address signatureValidationAlgorithm,
     *         bytes memory signer,
     *         address policy,
     *         bytes memory policyData,
     *         bytes memory permissionEnableData,
     *         bytes memory permissionEnableSignature
     */

    using ModeLib for ExecutionMode;

    IEntryPoint public immutable ep;

    constructor(address _entryPoint) {
        ep = IEntryPoint(_entryPoint);
    }

    function entryPoint() external view returns (address) {
        return address(ep);
    }

    // we expect the context to contain the full key,
    // as there can be 2d nonces and only context builder (sdk) knows it
    function getNonce(
        address smartAccount,
        bytes calldata context
    )
        external
        view
        returns (uint256 nonce)
    {
        uint192 key = uint192(bytes24(context[0:24])); // TODO: move to lib?
        nonce = ep.getNonce(address(smartAccount), key);
    }

    function getCallData(
        address, /* smartAccount */
        Execution[] calldata executions,
        bytes calldata context
    )
        external
        view
        returns (bytes memory callData)
    {
        if (executions.length == 0) {
            revert("No executions provided");
        }

        ExecutionMode mode = ExecutionMode.wrap(bytes32(context[24:56]));  // TODO: move to lib?
        (CallType callType, ExecType execType) = mode.decodeBasic();

        if (callType == CALLTYPE_SINGLE) {
            callData = abi.encodeCall(
                IERC7579Account.execute,
                (
                    mode,
                    ExecutionLib.encodeSingle(
                        executions[0].target, executions[0].value, executions[0].callData
                    )
                )
            );
        } else if (callType == CALLTYPE_BATCH) {
            callData = abi.encodeCall(
                IERC7579Account.execute,
                (mode, ExecutionLib.encodeBatch(executions))
            );
        } else {
            revert UnsupportedCallType(callType);
        }
        // TODO: add delegatecall?
    }

    function formatSignature(
        address smartAccount,
        PackedUserOperation calldata userOperation,
        bytes calldata context
    )
        external
        view
        returns (bytes memory)
    {
        if (context.length < 88) {
            revert("Context too short");
            // context should contain at least 24 bytes nonce_key, 32 bytes mode, and 32 bytes signerId
        } else if (context.length == 88) {
            // if by some (weird) reason the context contains only 32bytes signerId on top of 
            // the nonce_key and mode => then it is a context for just using the permission
            return abi.encodePacked(bytes1(0x00), context[56:88], userOperation.signature);
        }
        
        address permissionValidator = address(bytes20(context[0:20]));
        bytes calldata permEnableData = context[56:];

        try IPermissionEnabled(permissionValidator).isPermissionEnabled(permEnableData, smartAccount) returns (bool isEnabled, bytes32 _signerId) {
            if(isEnabled) {
                return abi.encodePacked(bytes1(0x00), _signerId, userOperation.signature);
            } else {
                console2.log("userOpBuilder: permission not enabled");
                // parse data from context and repack it along with the userOp.sig
                return abi.encodePacked(
                                bytes1(0x01), 
                                permEnableData,
                                userOperation.signature
                            );
            }
        } catch (bytes memory error) {
            revert InvalidPermission(error);
        }
        
        // context is always created to enable permission, so it always contains the permission enable data
        // however we do not need it if the permission has already been enabled once 
        // as not all the permissions are one-time permissions.
        // some dApps may leverage the permission several times, but they will have same context for all userOps.
        
        // so we need to check if the permission has been enabled or not

        // a) if enabled, just add enableMode = 0 and signerId to the userOp.signature

        // b) otherwise, append enableMode = 1 and take the full context[56:] and append it to signature

        /*

        0x010100000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000003400000000000000000000000000000000000000000000000000000000000000050000000000000000199e4794b5a7561aa7b7ac0b642775986aaebd65bd588f2c72290ade4348158330000000000007a6999e4794b5a7561aa7b7ac0b642775986aaebd65bd588f2c72290ade43481583300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005515cf58144ef33af1e14b5208015d11f9143e27b9a788e6f7983562f7b34faad35e5bea0d3dd430ada12caada7063f2c635efd81c12a25e0542af144a43f115fea6d3172f07485594e723c1713dd961bd86d4897d1b000000000000000000000000000000000000000000000000000000000000000000000000000000000001884636e64e77614c24f3502c820771755d0543731e5151aaf71b2a609bd6b8f13e01020201212224d2f2d262cd093ee13240ca4873fccbba3c00000014541b0d48a6e7ceda3a2603d13aa7338d3356acba2a07706473244bc757e10f2a9e86fb532828afe300000020000000000000000000000000000000000000000000000000000000000000000a3d7ebc40af7092e3f1c81f2e996cba5cae2090d700000020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc92773bb6d2f7693a7561aaf3c2e3f3d161b7b70e085358ac9ed27b74ad45a462a07706473244bc757e10f2a9e86fb532828afe3000000200000000000000000000000000000000000000000000000000000000000000005d16d567549a2a2a2005aeacf7fb193851603dd70000000200000000000000000000000006426266800000000000000000000000064262280d16d567549a2a2a2005aeacf7fb193851603dd700000002000000000000000000000000064264de7000000000000000000000000642624740000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041a5d374f264a2f262b02e3e806a36f2399381f8695944f9c6176360fee7d1e9272c6ac684739ed2a691799b6365fe472595dd875e35bbb702a7a6b55057bdc65b1c00000000000000000000000000000000000000000000000000000000000000

        0x0101000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000050000000000000000199e4794b5a7561aa7b7ac0b642775986aaebd65bd588f2c72290ade4348158330000000000007a6999e4794b5a7561aa7b7ac0b642775986aaebd65bd588f2c72290ade43481583300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005515cf58144ef33af1e14b5208015d11f9143e27b9a788e6f7983562f7b34faad35e5bea0d3dd430ada12caada7063f2c635efd81c12a25e0542af144a43f115fea6d3172f07485594e723c1713dd961bd86d4897d1b000000000000000000000000000000000000000000000000000000000000000000000000000000000001884636e64e77614c24f3502c820771755d0543731e5151aaf71b2a609bd6b8f13e01020201212224d2f2d262cd093ee13240ca4873fccbba3c00000014541b0d48a6e7ceda3a2603d13aa7338d3356acba2a07706473244bc757e10f2a9e86fb532828afe300000020000000000000000000000000000000000000000000000000000000000000000a3d7ebc40af7092e3f1c81f2e996cba5cae2090d700000020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc92773bb6d2f7693a7561aaf3c2e3f3d161b7b70e085358ac9ed27b74ad45a462a07706473244bc757e10f2a9e86fb532828afe3000000200000000000000000000000000000000000000000000000000000000000000005d16d567549a2a2a2005aeacf7fb193851603dd70000000200000000000000000000000006426266800000000000000000000000064262280d16d567549a2a2a2005aeacf7fb193851603dd700000002000000000000000000000000064264de700000000000000000000000064262474000000000000000000000000000000000000000000000000

        */
        
        
    }

    /* 
    TODO: add formatERC1271Signature(
        address smartAccount,
        bytes calldata signature,
        bytes calldata context
    )
    */
}

