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
     *    2. ExecutionMode as per ERC-7579 (32 bytes)
     *    3. bytes1 permissionIndex
     *    4. permissionEnableData,
             permissionEnableDataSignature,
            bytes calldata permissionData,
            bytes calldata cleanSig
     *         
     * 
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
    }

    /* 
    TODO: add formatERC1271Signature(
        address smartAccount,
        bytes calldata signature,
        bytes calldata context
    )
    */
}

