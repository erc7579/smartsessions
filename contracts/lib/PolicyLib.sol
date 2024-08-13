// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "../DataTypes.sol";
import { PackedUserOperation } from "modulekit/external/ERC4337.sol";
// import {
//     AddressArrayMap4337 as AddressVec,
//     Bytes32ArrayMap4337 as BytesVec,
//     ArrayMap4337Lib as AddressVecLib
// } from "contracts/lib/ArrayMap4337Lib.sol";

import { AssociatedArrayLib } from "../utils/AssociatedArrayLib.sol";

import { Execution, ExecutionLib2 as ExecutionLib } from "./ExecutionLib2.sol";

import "forge-std/console2.sol";

import {
    ModeLib,
    ModeCode as ExecutionMode,
    ExecType,
    CallType,
    CALLTYPE_BATCH,
    CALLTYPE_SINGLE,
    CALLTYPE_STATIC,
    CALLTYPE_DELEGATECALL,
    EXECTYPE_DEFAULT,
    EXECTYPE_TRY
} from "erc7579/lib/ModeLib.sol";

import { ERC7579ValidatorBase } from "modulekit/Modules.sol";
import { ValidationDataLib } from "contracts/lib/ValidationDataLib.sol";
import { IActionPolicy } from "../interfaces/IPolicy.sol";
import { IdLib } from "./IdLib.sol";

import { SENTINEL, SentinelList4337Lib } from "sentinellist/SentinelList4337.sol";

library PolicyLib {
    using SentinelList4337Lib for SentinelList4337Lib.SentinelList;
    using ExecutionLib for *;
    using IdLib for *;
    using PolicyLib for *;
    using AssociatedArrayLib for *;
    using ValidationDataLib for ERC7579ValidatorBase.ValidationData;

    error PolicyAlreadyUsed(address policy);
    error PolicyViolation(SignerId signerId, address policy);
    error UnsupportedCallType(CallType callType);
    error NoPoliciesSet(SignerId signerId);
    error PartlyEnabledPolicies();
    error PartlyEnabledActions();

    function isFailed(ERC7579ValidatorBase.ValidationData packedData) internal pure returns (bool sigFailed) {
        sigFailed = (ERC7579ValidatorBase.ValidationData.unwrap(packedData) & 1) == 1;
    }

    function check(
        Policy storage $self,
        PackedUserOperation calldata userOp,
        SignerId signer,
        bytes memory callOnIPolicy,
        uint256 minPoliciesToEnforce
    )
        internal
        returns (ERC7579ValidatorBase.ValidationData vd)
    {
        address account = userOp.sender;
        (address[] memory policies,) = $self.policyList[signer].getEntriesPaginated(account, SENTINEL, 32);
        uint256 length = policies.length;
        if (minPoliciesToEnforce > length) revert NoPoliciesSet(signer);

        // iterate over all policies and intersect the validation data
        for (uint256 i; i < length; i++) {
            uint256 validationDataFromPolicy = uint256(bytes32(policies[i].safeCall({ callData: callOnIPolicy })));
            vd = ERC7579ValidatorBase.ValidationData.wrap(validationDataFromPolicy);
            if (vd.isFailed()) revert PolicyViolation(signer, policies[i]);
            vd = vd.intersectValidationData(vd);
        }
    }

    function checkSingle7579Exec(
        mapping(ActionId => Policy) storage $policies,
        PackedUserOperation calldata userOp,
        SignerId signerId,
        address target,
        uint256 value,
        bytes calldata callData
    )
        internal
        returns (ERC7579ValidatorBase.ValidationData vd)
    {
        ActionId actionId = target.toActionId(callData);
        vd = $policies[actionId].check({
            userOp: userOp,
            signer: signerId,
            callOnIPolicy: abi.encodeCall(
                IActionPolicy.checkAction,
                (
                    signerId.toSessionId(actionId),
                    target, // target
                    value, // value
                    callData, // data
                    userOp
                )
            ),
            minPoliciesToEnforce: 0
        });
    }

    function checkBatch7579Exec(
        mapping(ActionId => Policy) storage $policies,
        PackedUserOperation calldata userOp,
        SignerId signerId
    )
        internal
        returns (ERC7579ValidatorBase.ValidationData vd)
    {
        Execution[] calldata executions = userOp.callData.decodeUserOpCallData().decodeBatch();
        uint256 length = executions.length;
        for (uint256 i; i < length; i++) {
            Execution calldata execution = executions[i];

            vd = vd.intersectValidationData(
                checkSingle7579Exec({
                    $policies: $policies,
                    userOp: userOp,
                    signerId: signerId,
                    target: execution.target,
                    value: execution.value,
                    callData: execution.callData
                })
            );
        }
    }

    function safeCall(address target, bytes memory callData) internal returns (bytes memory returnData) {
        bool success;
        (success, returnData) = target.call(callData);
        if (!success) revert();
    }

    function areEnabled(
        Policy storage $policies,
        SignerId signerId,
        SessionId sessionId,
        address smartAccount,
        PolicyData[] memory policyDatas
    )
        internal
        view
        returns (bool)
    {
        uint256 length = policyDatas.length;
        if (length == 0) return true; // 0 policies are always enabled lol
        uint256 enabledPolicies;
        for (uint256 i; i < length; i++) {
            PolicyData memory policyData = policyDatas[i];
            ISubPermission policy = ISubPermission(policyData.policy);
            if (
                $policies.policyList[signerId].contains(smartAccount, address(policy))
                    && policy.isInitialized(smartAccount, sessionId)
            ) enabledPolicies++;
        }
        if (enabledPolicies == 0) return false;
        else if (enabledPolicies == length) return true;
        else revert PartlyEnabledPolicies();
    }

    function areEnabled(
        EnumerableActionPolicy storage $self,
        SignerId signerId,
        address smartAccount,
        ActionData[] memory actionPolicyDatas
    )
        internal
        view
        returns (bool)
    {
        uint256 length = actionPolicyDatas.length;
        uint256 actionsProperlyEnabled;
        for (uint256 i; i < length; i++) {
            ActionData memory actionPolicyData = actionPolicyDatas[i];
            ActionId actionId = actionPolicyData.actionId;
            SessionId sessionId = signerId.toSessionId(actionId, smartAccount);
            if (
                $self.actionPolicies[actionId].areEnabled(
                    signerId, sessionId, smartAccount, actionPolicyData.actionPolicies
                )
            ) actionsProperlyEnabled++;
        }
        if (actionsProperlyEnabled == 0) return false;
        else if (actionsProperlyEnabled == length) return true;
        else revert PartlyEnabledActions();
    }
}
