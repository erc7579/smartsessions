// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "../DataTypes.sol";
import { ISmartSession } from "../ISmartSession.sol";
import { PackedUserOperation } from "modulekit/external/ERC4337.sol";
import { AssociatedArrayLib } from "../utils/AssociatedArrayLib.sol";

import { Execution, ExecutionLib as ExecutionLib } from "./ExecutionLib.sol";
import { CallType, CALLTYPE_DELEGATECALL, EXECTYPE_DEFAULT, EXECTYPE_TRY } from "erc7579/lib/ModeLib.sol";

import { ERC7579ValidatorBase } from "modulekit/Modules.sol";
import { ValidationDataLib } from "contracts/lib/ValidationDataLib.sol";
import { IActionPolicy, I1271Policy } from "../interfaces/IPolicy.sol";
import { IdLib } from "./IdLib.sol";

import { IERC7579Account } from "erc7579/interfaces/IERC7579Account.sol";
import { EnumerableSet } from "../utils/EnumerableSet4337.sol";

library PolicyLib {
    using SentinelList4337Lib for SentinelList4337Lib.SentinelList;
    using EnumerableSet for EnumerableSet.AddressSet;
    using ExecutionLib for *;
    using IdLib for *;
    using PolicyLib for *;
    using AssociatedArrayLib for *;
    using ValidationDataLib for ValidationData;

    function isFailed(ValidationData packedData) internal pure returns (bool sigFailed) {
        sigFailed = (ValidationData.unwrap(packedData) & 1) == 1;
    }

    function check(
        Policy storage $self,
        PackedUserOperation calldata userOp,
        SignerId signerId,
        bytes memory callOnIPolicy,
        uint256 minPolicies
    )
        internal
        returns (ValidationData vd)
    {
        address account = userOp.sender;
        address[] memory policies = $self.policyList[signerId].values({ account: account });
        uint256 length = policies.length;
        if (minPolicies > length) revert ISmartSession.NoPoliciesSet(signerId);

        // iterate over all policies and intersect the validation data
        for (uint256 i; i < length; i++) {
            uint256 validationDataFromPolicy = uint256(bytes32(policies[i].safeCall({ callData: callOnIPolicy })));
            vd = ValidationData.wrap(validationDataFromPolicy);
            if (vd.isFailed()) revert ISmartSession.PolicyViolation(signerId, policies[i]);
            vd = vd.intersectValidationData(vd);
        }
    }

    function checkSingle7579Exec(
        mapping(ActionId => Policy) storage $policies,
        PackedUserOperation calldata userOp,
        SignerId signerId,
        address target,
        uint256 value,
        bytes calldata callData,
        uint256 minPolicies
    )
        internal
        returns (ValidationData vd)
    {
        bytes4 targetSig = bytes4(callData[0:4]);

        // In theory it could be possible, that a 7579 account calls its own execute function and thus bypasses the
        // policy check, since policies would be blind to the calldata in the nested execution
        if (targetSig == IERC7579Account.execute.selector && target == userOp.sender) {
            revert ISmartSession.InvalidSelfCall();
        }
        ActionId actionId = target.toActionId(targetSig);
        vd = $policies[actionId].check({
            userOp: userOp,
            signerId: signerId,
            callOnIPolicy: abi.encodeCall(
                IActionPolicy.checkAction, (signerId.toSessionId(actionId), userOp.sender, target, value, callData)
            ),
            minPolicies: minPolicies
        });
    }

    function checkBatch7579Exec(
        mapping(ActionId => Policy) storage $policies,
        PackedUserOperation calldata userOp,
        SignerId signerId,
        uint256 minPolicies
    )
        internal
        returns (ValidationData vd)
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
                    callData: execution.callData,
                    minPolicies: minPolicies
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
        else revert ISmartSession.PartlyEnabledPolicies();
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
        else revert ISmartSession.PartlyEnabledActions();
    }

    function checkERC1271(
        Policy storage $self,
        address account,
        address requestSender,
        bytes32 hash,
        bytes calldata signature,
        SignerId signerId,
        SessionId sessionId,
        uint256 minPoliciesToEnforce
    )
        internal
        view
        returns (bool valid)
    {
        address[] memory policies = $self.policyList[signerId].values({ account: account });
        uint256 length = policies.length;
        if (minPoliciesToEnforce > length) revert ISmartSession.NoPoliciesSet(signerId);

        // iterate over all policies and intersect the validation data
        for (uint256 i; i < length; i++) {
            valid = I1271Policy(policies[i]).check1271SignedAction({
                id: sessionId,
                requestSender: requestSender,
                account: account,
                hash: hash,
                signature: signature
            });
            if (!valid) return false;
        }
    }
}
