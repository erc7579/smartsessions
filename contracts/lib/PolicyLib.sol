// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "../DataTypes.sol";
import { ISmartSession } from "../ISmartSession.sol";
import { IPolicy } from "../interfaces/IPolicy.sol";
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
    using EnumerableSet for EnumerableSet.AddressSet;
    using ExecutionLib for *;
    using IdLib for *;
    using PolicyLib for *;
    using AssociatedArrayLib for *;
    using ValidationDataLib for ValidationData;

    function isFailed(ValidationData packedData) internal pure returns (bool sigFailed) {
        sigFailed = (ValidationData.unwrap(packedData) & 1) == 1;
    }

    /**
     * Multi-purpose helper function that interacts with external Policy Contracts.
     * This function can be used to check different types of IPolicy functions.
     * The specific function to be called on the policy is determined by the callDataOnIPolicy parameter.
     *
     * @dev This function iterates through all policies associated with the given permissionId and account,
     *      calls each policy with the provided calldata, and intersects the resulting validation data.
     *      It will revert if any policy check fails or if there are fewer policies than the specified minimum.
     *
     * @param $self The Policy storage struct containing the list of policies.
     * @param userOp The PackedUserOperation to be validated.
     * @param permissionId The identifier for the permission being checked.
     * @param callOnIPolicy The encoded function call data to be executed on each policy contract.
     * @param minPolicies The minimum number of policies that must be present and checked.
     *
     * @return vd The intersected ValidationData result from all policy checks.
     */
    function check(
        Policy storage $self,
        PackedUserOperation calldata userOp,
        PermissionId permissionId,
        bytes memory callOnIPolicy,
        uint256 minPolicies
    )
        internal
        returns (ValidationData vd)
    {
        address account = userOp.sender;

        // Get the list of policies for the given permissionId and account
        address[] memory policies = $self.policyList[permissionId].values({ account: account });
        uint256 length = policies.length;

        // Ensure the minimum number of policies is met
        if (minPolicies > length) revert ISmartSession.NoPoliciesSet(permissionId);

        // Iterate over all policies and intersect the validation data
        for (uint256 i; i < length; i++) {
            // Call the policy contract with the provided calldata
            uint256 validationDataFromPolicy = uint256(bytes32(policies[i].safeCall({ callData: callOnIPolicy })));
            vd = ValidationData.wrap(validationDataFromPolicy);

            // Revert if the policy check fails
            if (vd.isFailed()) revert ISmartSession.PolicyViolation(permissionId, policies[i]);

            // Intersect the validation data from this policy with the accumulated result
            vd = vd.intersectValidationData(vd);
        }
    }

    /**
     * Same as check but will not revert if minimum number of policies is not met.
     * This allows a second check with the FALLBACK_ACTIONID.
     *
     * @param $self The Policy storage struct containing the list of policies.
     * @param userOp The PackedUserOperation to be validated.
     * @param permissionId The identifier for the permission being checked.
     * @param callOnIPolicy The encoded function call data to be executed on each policy contract.
     * @param minPolicies The minimum number of policies that must be present and checked.
     *
     * @return vd The intersected ValidationData result from all policy checks.
     */
    function tryCheck(
        Policy storage $self,
        PackedUserOperation calldata userOp,
        PermissionId permissionId,
        bytes memory callOnIPolicy,
        uint256 minPolicies
    )
        internal
        returns (ValidationData vd)
    {
        address account = userOp.sender;

        // Get the list of policies for the given permissionId and account
        address[] memory policies = $self.policyList[permissionId].values({ account: account });
        uint256 length = policies.length;

        // Ensure the minimum number of policies is met
        if (minPolicies > length) {
            return RETRY_WITH_FALLBACK;
        }

        // Iterate over all policies and intersect the validation data
        for (uint256 i; i < length; i++) {
            // Call the policy contract with the provided calldata
            uint256 validationDataFromPolicy = uint256(bytes32(policies[i].safeCall({ callData: callOnIPolicy })));
            vd = ValidationData.wrap(validationDataFromPolicy);

            // Revert if the policy check fails
            if (vd.isFailed()) revert ISmartSession.PolicyViolation(permissionId, policies[i]);

            // Intersect the validation data from this policy with the accumulated result
            vd = vd.intersectValidationData(vd);
        }
    }

    /**
     * Checks policies for a single ERC7579 execution within a user operation.
     * This function validates the execution against relevant action policies.
     *
     * @dev This function prevents potential bypass of policy checks through nested executions
     *      by disallowing self-calls to the execute function.
     *
     * @param $policies The storage mapping of action policies.
     * @param userOp The packed user operation being validated.
     * @param permissionId The identifier for the permission being checked.
     * @param target The target address of the execution.
     * @param value The ETH value being sent with the execution.
     * @param callData The call data of the execution.
     * @param minPolicies The minimum number of policies that must be checked.
     *
     * @return vd The validation data resulting from the policy checks.
     */
    function checkSingle7579Exec(
        mapping(ActionId => Policy) storage $policies,
        PackedUserOperation calldata userOp,
        PermissionId permissionId,
        address target,
        uint256 value,
        bytes calldata callData,
        uint256 minPolicies
    )
        internal
        returns (ValidationData vd)
    {
        // Extract the function selector from the call data
        bytes4 targetSig = bytes4(callData[0:4]);

        // Prevent potential bypass of policy checks through nested self executions
        if (targetSig == IERC7579Account.execute.selector && target == userOp.sender) {
            revert ISmartSession.InvalidSelfCall();
        }

        // Generate the action ID based on the target and function selector
        ActionId actionId = target.toActionId(targetSig);

        // Check the relevant action policy
        vd = $policies[actionId].tryCheck({
            userOp: userOp,
            permissionId: permissionId,
            callOnIPolicy: abi.encodeCall(
                IActionPolicy.checkAction, (permissionId.toConfigId(actionId), userOp.sender, target, value, callData)
            ),
            minPolicies: minPolicies
        });
        if (vd == RETRY_WITH_FALLBACK) {
            vd = $policies[FALLBACK_ACTIONID].check({
                userOp: userOp,
                permissionId: permissionId,
                callOnIPolicy: abi.encodeCall(
                    IActionPolicy.checkAction, (permissionId.toConfigId(actionId), userOp.sender, target, value, callData)
                ),
                minPolicies: minPolicies
            });
        }
        return vd;
    }

    /**
     * Checks policies for a batch of ERC7579 executions within a user operation.
     * This function iterates through each execution in the batch and validates them against relevant action policies.
     *
     * @dev This function decodes the batch of executions from the user operation's call data,
     *      then applies policy checks to each execution individually.
     *      The validation results are intersected to ensure all executions pass the policy checks.
     *
     * @param $policies The storage mapping of action policies.
     * @param userOp The packed user operation being validated.
     * @param permissionId The identifier for the permission being checked.
     * @param minPolicies The minimum number of policies that must be checked for each execution.
     *
     * @return vd The final validation data resulting from intersecting all policy checks.
     */
    function checkBatch7579Exec(
        mapping(ActionId => Policy) storage $policies,
        PackedUserOperation calldata userOp,
        PermissionId permissionId,
        uint256 minPolicies
    )
        internal
        returns (ValidationData vd)
    {
        // Decode the batch of 7579 executions from the user operation's call data
        Execution[] calldata executions = userOp.callData.decodeUserOpCallData().decodeBatch();
        uint256 length = executions.length;

        // Iterate through each execution in the batch
        for (uint256 i; i < length; i++) {
            Execution calldata execution = executions[i];

            // Check policies for the current execution and intersect the result with previous checks
            vd = vd.intersectValidationData(
                checkSingle7579Exec({
                    $policies: $policies,
                    userOp: userOp,
                    permissionId: permissionId,
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

    /**
     * Checks the validity of an ERC1271 signature against all relevant policies.
     *
     * @dev This function iterates through all policies for the given permission and checks
     *      the signature validity using each policy's check1271SignedAction function.
     *
     * @param $self The storage reference to the Policy struct.
     * @param account The address of the account associated with the signature.
     * @param requestSender The address of the entity requesting the signature check.
     * @param hash The hash of the signed data.
     * @param signature The signature to be validated.
     * @param permissionId The identifier of the permission being checked.
     * @param configId The configuration identifier.
     * @param minPoliciesToEnforce The minimum number of policies that must be checked.
     *
     * @return valid Returns true if the signature is valid according to all policies, false otherwise.
     */
    function checkERC1271(
        Policy storage $self,
        address account,
        address requestSender,
        bytes32 hash,
        bytes calldata signature,
        PermissionId permissionId,
        ConfigId configId,
        uint256 minPoliciesToEnforce
    )
        internal
        view
        returns (bool valid)
    {
        address[] memory policies = $self.policyList[permissionId].values({ account: account });
        uint256 length = policies.length;
        if (minPoliciesToEnforce > length) revert ISmartSession.NoPoliciesSet(permissionId);

        // iterate over all policies and intersect the validation data
        for (uint256 i; i < length; i++) {
            valid = I1271Policy(policies[i]).check1271SignedAction({
                id: configId,
                requestSender: requestSender,
                account: account,
                hash: hash,
                signature: signature
            });
            // If any policy check fails, return false immediately
            if (!valid) return false;
        }
    }

    /**
     * Checks if the specified policies are enabled for a given permission and smart account.
     *
     * @dev This function verifies that all specified policies are both present in the policy list
     *      and initialized for the given smart account and config.
     *
     * @param $policies The storage reference to the Policy struct.
     * @param permissionId The identifier of the permission being checked.
     * @param configId The configuration identifier.
     * @param smartAccount The address of the smart account.
     * @param policyDatas An array of PolicyData structs representing the policies to check.
     *
     * @return bool Returns true if all policies are enabled, false if none are enabled.
     *              Reverts if policies are partially enabled.
     */
    function areEnabled(
        Policy storage $policies,
        PermissionId permissionId,
        ConfigId configId,
        address smartAccount,
        PolicyData[] memory policyDatas
    )
        internal
        view
        returns (bool)
    {
        uint256 length = policyDatas.length;

        // TODO: should we change this to false?
        if (length == 0) return true; // 0 policies are always enabled lol
        uint256 enabledPolicies;
        for (uint256 i; i < length; i++) {
            PolicyData memory policyData = policyDatas[i];
            IPolicy policy = IPolicy(policyData.policy);

            // Check if policy is in the list and initialized for the smart account,
            // this smart session and configId
            if (
                $policies.policyList[permissionId].contains(smartAccount, address(policy))
                    && policy.isInitialized(smartAccount, address(this), configId)
            ) enabledPolicies++;
        }
        if (enabledPolicies == 0) return false;
        else if (enabledPolicies == length) return true;
        else revert ISmartSession.PartlyEnabledPolicies();
    }

    /**
     * Checks if the specified action policies are enabled for a given permission and smart account.
     *
     * @dev This function verifies that all specified action policies are enabled.
     *
     * @param $self The storage reference to the EnumerableActionPolicy struct.
     * @param permissionId The identifier of the permission being checked.
     * @param smartAccount The address of the smart account.
     * @param actionPolicyDatas An array of ActionData structs representing the action policies to check.
     *
     * @return bool Returns true if all action policies are enabled, false if none are enabled.
     *              Reverts if action policies are partially enabled.
     */
    function areEnabled(
        EnumerableActionPolicy storage $self,
        PermissionId permissionId,
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
            ActionId actionId = actionPolicyData.actionTarget.toActionId(actionPolicyData.actionTargetSelector);
            ConfigId configId = permissionId.toConfigId(actionId, smartAccount);
            // Check if the action policy is enabled
            if (
                $self.actionPolicies[actionId].areEnabled(
                    permissionId, configId, smartAccount, actionPolicyData.actionPolicies
                )
            ) actionsProperlyEnabled++;
        }
        if (actionsProperlyEnabled == 0) return false;
        else if (actionsProperlyEnabled == length) return true;
        else revert ISmartSession.PartlyEnabledActions();
    }
}
