import "../DataTypes.sol";
import { PackedUserOperation } from "modulekit/external/ERC4337.sol";
import {
    AddressArrayMap4337 as AddressVec,
    Bytes32ArrayMap4337 as BytesVec,
    ArrayMap4337Lib as AddressVecLib
} from "contracts/utils/lib/ArrayMap4337Lib.sol";

import { Execution, ExecutionLib } from "erc7579/lib/ExecutionLib.sol";

import {
    ModeLib,
    ExecutionMode,
    ExecType,
    CallType,
    CALLTYPE_BATCH,
    CALLTYPE_SINGLE,
    CALLTYPE_STATIC,
    CALLTYPE_DELEGATECALL,
    EXECTYPE_DEFAULT,
    EXECTYPE_TRY
} from "contracts/utils/lib/ModeLib.sol";

import { ERC7579ValidatorBase } from "modulekit/Modules.sol";
import { ValidationDataLib } from "contracts/utils/lib/ValidationDataLib.sol";
import { IActionPolicy } from "../../interfaces/IPolicies.sol";

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
     * @param callData the calldata of what should be invoked on the policy
     */
    function check(
        mapping(SignerId => AddressVec) storage $policies,
        PackedUserOperation calldata userOp,
        SignerId signer,
        bytes memory callData
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
                uint256(bytes32(policy.fwdCall({ forAccount: account, callData: callData })));
            vd = vd.intersectValidationData(ERC7579ValidatorBase.ValidationData.wrap(validationDataFromPolicy));
        }
    }

    function checkExecution(
        mapping(ActionId => mapping(SignerId => AddressVec)) storage $policies,
        PackedUserOperation calldata userOp,
        SignerId signerId
    )
        internal
        returns (ERC7579ValidatorBase.ValidationData vd)
    {
        ExecutionMode mode = ExecutionMode.wrap(bytes32(userOp.callData[4:36]));
        CallType callType;
        ExecType execType;

        bytes calldata executionCalldata = userOp.callData;

        // solhint-disable-next-line no-inline-assembly
        assembly {
            callType := mode
            execType := shl(8, mode)
        }
        /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
        /*                   REVERT ON FAILED EXEC                    */
        /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
        if (execType == EXECTYPE_DEFAULT) {
            // DEFAULT EXEC & BATCH CALL
            if (callType == CALLTYPE_BATCH) {
                Execution[] calldata executions = executionCalldata.decodeBatch();
                uint256 length = executions.length;
                for (uint256 i; i < length; i++) {
                    Execution calldata execution = executions[i];

                    ActionId actionId = execution.target.toActionId(execution.callData);
                    ERC7579ValidatorBase.ValidationData _vd = $policies[actionId].check({
                        userOp: userOp,
                        signer: signerId,
                        callData: abi.encodeCall(
                            IActionPolicy.checkAction,
                            (
                                keccak256(abi.encodePacked(signerId, actionId)), // actionId
                                execution.target, // target
                                execution.value, // value
                                execution.callData, // data
                                userOp // userOp
                            )
                        )
                    });
                    vd = vd.intersectValidationData(_vd);
                }
            }
            // DEFAULT EXEC & SINGLE CALL
            else if (callType == CALLTYPE_SINGLE) {
                (address target, uint256 value, bytes calldata callData) = executionCalldata.decodeSingle();
                ActionId actionId = target.toActionId(callData);

                vd = $policies[actionId].check({
                    userOp: userOp,
                    signer: signerId,
                    callData: abi.encodeCall(
                        IActionPolicy.checkAction,
                        (
                            keccak256(abi.encodePacked(signerId, actionId)), // actionId
                            target, // target
                            value, // value
                            callData, // data
                            userOp // userOp
                        )
                    )
                });
            }
            // DEFAULT EXEC & DELEGATECALL
            else if (callType == CALLTYPE_DELEGATECALL) {
                address target = address(bytes20(executionCalldata[:20]));
                bytes calldata callData = executionCalldata[20:];
                ActionId actionId = target.toActionId(callData);

                vd = $policies[actionId].check({
                    userOp: userOp,
                    signer: signerId,
                    callData: abi.encodeCall(
                        IActionPolicy.checkAction,
                        (
                            keccak256(abi.encodePacked(signerId, actionId)), // actionId
                            target, // target
                            0, // value
                            callData, // data
                            userOp // userOp
                        )
                    )
                });
            }
            // handle unsupported calltype
            else {
                revert UnsupportedCallType(callType);
            }
        }
    }

    function toActionId(address target, bytes calldata data) internal pure returns (ActionId actionId) {
        actionId = ActionId.wrap(keccak256(abi.encodePacked(target, data.length >= 4 ? bytes4(data[0:4]) : bytes4(0))));
    }
}
