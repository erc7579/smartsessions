import "../DataTypes.sol";
import { PackedUserOperation } from "modulekit/external/ERC4337.sol";
import {
    AddressArrayMap4337 as AddressVec,
    Bytes32ArrayMap4337 as BytesVec,
    ArrayMap4337Lib as AddressVecLib
} from "contracts/lib/ArrayMap4337Lib.sol";

import { Execution, ExecutionLib } from "erc7579/lib/ExecutionLib.sol";
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

import { SENTINEL, SentinelList4337Lib } from "sentinellist/SentinelList4337.sol";

library PolicyLib {
    using SentinelList4337Lib for SentinelList4337Lib.SentinelList;
    using ExecutionLib for *;
    using PolicyLib for *;
    using AddressVecLib for *;
    using ValidationDataLib for ERC7579ValidatorBase.ValidationData;

    error PolicyAlreadyUsed(address policy);
    error PolicyViolation(SignerId signerId, address policy);
    error UnsupportedCallType(CallType callType);
    error NoPoliciesSet(SignerId signerId);

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
        ActionId actionId = toActionId(target, callData);

        vd = $policies[actionId].check({
            userOp: userOp,
            signer: signerId,
            callOnIPolicy: abi.encodeCall(
                IActionPolicy.checkAction,
                (
                    sessionId(signerId, actionId), // actionId
                    userOp.sender,
                    target, // target
                    value, // value
                    callData // data
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
        Execution[] calldata executions = userOp.callData.decodeBatch();
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
}
