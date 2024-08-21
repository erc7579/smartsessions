// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { IUserOperationBuilder, PackedUserOperation, Execution } from "./IUserOpBuilder.sol";
import { IEntryPoint } from "modulekit/external/ERC4337.sol";
import { Exec } from "account-abstraction/utils/Exec.sol";
import { IERC7579Account } from "erc7579/interfaces/IERC7579Account.sol";
import { ModeCode as ExecutionMode, ExecType, CallType, CALLTYPE_BATCH, CALLTYPE_SINGLE } from "erc7579/lib/ModeLib.sol";
import { EncodeLib } from "../lib/EncodeLib.sol";
import { ExecutionLib as ExecutionLib } from "../lib/ExecutionLib.sol";
import "../DataTypes.sol";
import "forge-std/Console2.sol";

interface IPermissionEnabled {
    function isPermissionEnabled(
        SignerId signerId,
        address smartAccount,
        PolicyData[] memory userOpPolicies,
        PolicyData[] memory erc1271Policies,
        ActionData[] memory actions
    )
        external
        view
        returns (bool);
}

contract UserOperationBuilder is IUserOperationBuilder {
    /**
     *    PermissionContext is a bytes array : ...
     *    0-24 : nonce key
     *    24-56: execution mode
     *    56-88: signerId
     *    88: abi.encode(EnableSessions)
     */
    using ExecutionLib for *;
    using EncodeLib for *;

    IEntryPoint public immutable ep;

    constructor(address _entryPoint) {
        ep = IEntryPoint(_entryPoint);
    }

    function entryPoint() external view returns (address) {
        return address(ep);
    }

    // we expect the context to contain the full key,
    // as there can be 2d nonces and only context builder (sdk) knows it
    function getNonce(address smartAccount, bytes calldata context) external view returns (uint256 nonce) {
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

        ExecutionMode mode = ExecutionMode.wrap(bytes32(context[24:56])); // TODO: move to lib?
        CallType callType;
        assembly {
            callType := mode
        }

        if (callType == CALLTYPE_SINGLE) {
            callData = abi.encodeCall(
                IERC7579Account.execute,
                (mode, ExecutionLib.encodeSingle(executions[0].target, executions[0].value, executions[0].callData))
            );
        } else if (callType == CALLTYPE_BATCH) {
            callData = abi.encodeCall(IERC7579Account.execute, (mode, ExecutionLib.encodeBatch(executions)));
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
        }

        SignerId signerId = SignerId.wrap(bytes32(context[56:88]));

        if (context.length == 88) {
            // if by some (weird) reason the context contains only 32bytes signerId on top of
            // the nonce_key and mode => then it is a context for just using the permission
            return EncodeLib.encodeUse(signerId, userOperation.signature);
        }

        address permissionValidator = address(bytes20(context[0:20]));
        EnableSessions memory enableData = abi.decode(context[88:], (EnableSessions));

        try IPermissionEnabled(permissionValidator).isPermissionEnabled(
            signerId,
            smartAccount,
            enableData.userOpPolicies,
            enableData.erc7739Policies.erc1271Policies,
            enableData.actions
        ) returns (bool isEnabled) {
            if (isEnabled) {
                return EncodeLib.encodeUse(signerId, userOperation.signature);
            } else {
                return EncodeLib.encodeEnable(signerId, userOperation.signature, enableData);
            }
        } catch (bytes memory error) {
            revert InvalidPermission(error);
        }
    }

    /* 
    TODO: add formatERC1271Signature(
        address smartAccount,
        bytes calldata signature,
        bytes calldata context
    )
    */
}
