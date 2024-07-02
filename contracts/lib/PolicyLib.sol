import "../DataTypes.sol";
import { PackedUserOperation } from "modulekit/external/ERC4337.sol";
import {
    AddressArrayMap4337 as AddressVec,
    Bytes32ArrayMap4337 as BytesVec,
    ArrayMap4337Lib as AddressVecLib
} from "contracts/lib/ArrayMap4337Lib.sol";

import { Execution, ExecutionLib } from "erc7579/lib/ExecutionLib.sol";

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

import "./TrustedForwardLib.sol";

library PolicyLib {
    using ExecutionLib for *;
    using PolicyLib for *;
    using AddressVecLib for *;
    using TrustedForwardLib for address;
    using ValidationDataLib for ERC7579ValidatorBase.ValidationData;

    error PolicyAlreadyUsed(address policy);
    error UnsupportedCallType(CallType callType);

    /**
     * Generic function that works with all policy types.
     * @param $policies the storage mapping of the policies that need to be checked
     * @param userOp 4337 userOp
     * @param signer signerId that will be forwareded to the policies
     * @param callOnIPolicy the calldata of what should be invoked on the policy
     */
    function check(
        mapping(SignerId => AddressVec) storage $policies,
        PackedUserOperation calldata userOp,
        SignerId signer,
        bytes memory callOnIPolicy
    )
        internal
        returns (ERC7579ValidatorBase.ValidationData vd)
    {
        address account = userOp.sender;
        AddressVec storage $addresses = $policies[signer];

        uint256 length = $addresses.length(account);

        // iterate over all policies and intersect the validation data
        for (uint256 i; i < length; i++) {
            address policy = $addresses.get(account, i);
            uint256 validationDataFromPolicy =
                uint256(bytes32(policy.fwdCall({ forAccount: account, callData: callOnIPolicy })));
            vd = vd.intersectValidationData(ERC7579ValidatorBase.ValidationData.wrap(validationDataFromPolicy));
        }
    }

    function toActionId(address target, bytes calldata data) internal pure returns (ActionId actionId) {
        actionId = ActionId.wrap(keccak256(abi.encodePacked(target, data.length >= 4 ? bytes4(data[0:4]) : bytes4(0))));
    }

    function checkSingle7579Exec(
        mapping(ActionId => mapping(SignerId => AddressVec)) storage $policies,
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
                    toActionPolicyId(signerId, actionId), // actionId
                    target, // target
                    value, // value
                    callData, // data
                    userOp // userOp
                )
            )
        });
    }

    function checkBatch7579Exec(
        mapping(ActionId => mapping(SignerId => AddressVec)) storage $policies,
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
}
