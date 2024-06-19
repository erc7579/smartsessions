// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { ERC7579ValidatorBase, ERC7579ExecutorBase } from "modulekit/Modules.sol";
import { PackedUserOperation } from "modulekit/external/ERC4337.sol";
import { AddressArray, AddressArrayLib } from "contracts/utils/lib/AddressArrayLib.sol";
import { ModeLib, ExecutionMode, ExecType, CallType, CALLTYPE_BATCH, CALLTYPE_SINGLE, CALLTYPE_STATIC, CALLTYPE_DELEGATECALL, EXECTYPE_DEFAULT, EXECTYPE_TRY } from "contracts/utils/lib/ModeLib.sol";
import { ExecutionLib } from "erc7579/lib/ExecutionLib.sol";
import { ValidationDataLib } from "contracts/utils/lib/ValidationDataLib.sol";

// ??
//import { ERC7579ValidatorLib } from "module-bases/utils/ERC7579ValidatorLib.sol";

import { IPermissionManager, NO_SIGNATURE_VALIDATION_REQUIRED } from "contracts/interfaces/validators/IPermissionManager.sol";
import { IERC7579Account, Execution } from  "erc7579/interfaces/IERC7579Account.sol";
import { IModule as IERC7579Module } from "erc7579/interfaces/IERC7579Module.sol";
import { IAccountExecute} from "modulekit/external/ERC4337.sol";
import { ISignerValidator } from "contracts/interfaces/ISignerValidator.sol";
import { ITrustedForwarder } from "contracts/utils/interfaces/ITrustedForwarder.sol";
import { IUserOpPolicy, IActionPolicy, I1271Policy } from "contracts/interfaces/IPolicies.sol";
import { IAccountConfig } from "contracts/utils/interfaces/IAccountConfig.sol";
import { IERC165 } from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import "forge-std/console2.sol";

/**

TODO:
    - Enable permission along the first usage
        - renounce permissions even those are not used
    - Check Policies/Signers via Registry before enabling

 */

contract PermissionManager is ERC7579ValidatorBase, ERC7579ExecutorBase, IPermissionManager {
    /*//////////////////////////////////////////////////////////////////////////
                            CONSTANTS & STORAGE
    //////////////////////////////////////////////////////////////////////////*/

    // bytes32(uint256(keccak256('erc7579.module.permissionvalidator')) - 1)
    bytes32 constant PERMISSION_VALIDATOR_STORAGE_SLOT = 0x73a9885e8be4b58095971868aa2af983b5913f3e08c5b78a3ca0cb6b827458f8;

    using AddressArrayLib for AddressArray;
    using ExecutionLib for bytes;
    using ModeLib for ExecutionMode;
    using ValidationDataLib for ValidationData;

    struct PermissionValidatorStorage {
        // Note on the signerId. 
        // For now we assume signerId is known by dApp in some way
        // There are several approaches to it. For example it can be:
        // - keccak256(smartAccount.address + validationAlgo.address + salt)
        // in this case SDK or DApp have to store it somewhere to be able to use
        // Probably it's the best way to do it, since dApps already store things that they want to use later
        // such as signed offchain orders etc
        //
        // In case storing it somewhere for the SA is not the case, can introduce a specific flow
        // to retrieve it from the SignerValidationAlgo smart contract 
        // for example, every ISigner has getSignerId() method with its own list of args,
        // based on which it calculates the signerId
        // for example:
        // - simple eoa signer: keccak256(smartAccount.address + validationAlgo.address + ownerAddress)
        // - multisig signer: keccak256(smartAccount.address + validationAlgo.address + ownersAddresses + number of owners)
        // - etc
        // - it will work since SDK knows what signers are for this validation algo/ do they?
        // can discuss this with SDK guys

        mapping(SignerId => mapping (address smartAccount => address signerValidator)) signers;
        
        mapping(SignerId => mapping (address smartAccount => AddressArray)) userOpPolicies;  
        
        mapping(SignerId => mapping (ActionId => mapping (address smartAccount => AddressArray))) actionPolicies;  

        mapping(SignerId => mapping (address smartAccount => AddressArray)) erc1271Policies;
    }

    function _permissionValidatorStorage() internal pure returns (PermissionValidatorStorage storage state) {
        assembly {
            state.slot := PERMISSION_VALIDATOR_STORAGE_SLOT
        }
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     MODULE LOGIC
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * Validates PackedUserOperation
     *
     * @param userOp UserOperation to be validated
     * @param userOpHash Hash of the UserOperation to be validated
     *
     * @return vd (ValidatioData) => the result of the signature validation, which can be:
     *  - 0 if the signature is valid
     *  - 1 if the signature is invalid
     *  - <20-byte> aggregatorOrSigFail, <6-byte> validUntil and <6-byte> validAfter (see ERC-4337
     * for more details)
     */
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        external
        override
        returns (ValidationData vd)
    {   

        bytes4 selector = bytes4(userOp.callData[0:4]);

        //
        // ExecuteUserOp is ambiguous and not supported atm
        // Reason: since Smart Account implementation is free to call whatever it wants inside 
        // executeUserOp, we can never be sure which part of callData is going
        // to be executed if any at all, so we can't validate it with confidence
        // 
        // However, using executeUserOp is important functionality and can be crucial for
        // many usecases, so not supporting it is very limiting
        //
        // TODO: discuss it with auditors and potentially reconsider supporting the executeUserOp
        // with stating in the module documentation that it expects the actual calldata to be appended
        // to the executeUserOp.selector in the userOp.callData, otherwise it won't work as expected
        //
        if (selector == IAccountExecute.executeUserOp.selector) {
            revert ExecuteUserOpIsNotSupported();
            // selector = bytes4(userOp.callData[4:8]); // if supported
        }

        // Check enable mode flag (means we enable something before validating userOp.calldata)
        // enable mode can be : 
        // - enable signer => 
        //        in this case we know everything about the permissions we need to apply from 
        //        the signer enable object and we can save some SLOADs by not fetching the data
        //        from the storage in the _validate...Call() methods. 
        //        However, from code readability perspective it might be better to have a unified flow
        //        of just enbaling all first and then independently processing
        //        because in all other 'enable' cases we will have to SLOAD at least some data
        //
        //        Decided to just separate those flows for now. it makes things much easier to read,
        //        use, and understand.
        //        Can do optimization later to separate the flow that has all the required data
        //        to validate a userOp (or at least some actions) from the calldata (userOp.signature),
        //        not storage
        //        
        // - enable action permission for signer
        // - enable policy for signer
        // - enable policy for action permission

        SignerId signerId;
        bytes calldata cleanSig;
        address signerValidator;

        // if this is enable mode, we know the signer from it
        // otherwise we get the signer from the signature
        if(_isEnableMode(userOp.signature)) {
            console2.log("Enable Mode activated");
            (signerId, cleanSig, signerValidator) = _validateAndEnablePermissions(userOp);
        } else {
            signerId = SignerId.wrap(bytes32(userOp.signature[1:33]));
            cleanSig = userOp.signature[33:];
            signerValidator = _permissionValidatorStorage().signers[signerId][msg.sender];
        }

        /**  
         *  Check signature and policies
         */

        if (ISignerValidator(signerValidator).checkSignature(SignerId.unwrap(signerId), msg.sender, userOpHash, cleanSig) == EIP1271_FAILED) {
            return VALIDATION_FAILED;
        }
        console2.log("Signature validation at ISignerValidator.checkSignature passed");

        // Check userOp level Policies
        AddressArray storage policies = _permissionValidatorStorage().userOpPolicies[signerId][msg.sender];
        vd = _validateUserOpPolicies(signerId, policies, userOp);
        console2.log("UserOp Policies verification passed");

        //flows based on selector
        // CHANGE to receiving and intersecting validation data from policies
        if (selector == IERC7579Account.execute.selector) {
            vd = vd.intersectValidationData(_validate7579ExecuteCall(signerId, userOp));
        } else {
            vd = vd.intersectValidationData(
                // this is SA native function call. Such calls don't involve any value transfer
                _validateSingleExecution(signerId, userOp.sender, 0, userOp.callData, userOp)
            );
        }
        console2.log("Action policies validation passed");
    }

    /**
     * Validates an ERC-1271 signature
     *
     * @param sender The sender of the ERC-1271 call to the account
     * @param hash The hash of the message
     * @param signature The signature of the message
     *
     * @return sigValidationResult the result of the signature validation, which can be:
     *  - EIP1271_SUCCESS if the signature is valid
     *  - EIP1271_FAILED if the signature is invalid
     */
    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata signature
    )
        external
        view
        virtual
        override
        returns (bytes4 sigValidationResult)
    {   
        // for security reasons we do not allow requests from self,
        // otherwise anyone with 1271 permissions can enable any other permissions for themselves
        // TODO: TEST IT
        if (sender == address(this)) {
            return EIP1271_FAILED;          
        }        
        SignerId signerId = SignerId.wrap(bytes32(signature[1:33]));
        bytes memory cleanSig = signature[33:];
        address signerValidator = _permissionValidatorStorage().signers[signerId][msg.sender];
        
        // in some cases we do not need signer validation, then NO_SIGNATURE_VALIDATION_REQUIRED should be stored as signer validator for such signer id
        if (signerValidator != NO_SIGNATURE_VALIDATION_REQUIRED) {
            if (signerValidator == address(0)) {
                revert("SignerId not enabled");
            }
            if (ISignerValidator(signerValidator).checkSignature(SignerId.unwrap(signerId), msg.sender, hash, cleanSig) == EIP1271_FAILED) {
                return EIP1271_FAILED;
            }
            console2.log("1271 Signature validation happened");
        }

        // check policies
        // since it is vew, can safely introduce policies based on sender. 
        // it will be SA's job to ensure sender is correct, otherwise it will be unsafe for SA itself
        AddressArray storage policies = _permissionValidatorStorage().erc1271Policies[signerId][msg.sender];
        return _validateERC1271Policies(signerId, policies, sender, hash, signature);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     CONFIG
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * Initialize the module with the given data
     *
     * @param data The data to initialize the module with
     */
    function onInstall(bytes calldata data) external override {
        
        // the temporary onInstall that just enables some fixed set of policies per signer

        //if this module is being installed as a validator
        if(uint256(uint8(bytes1(data[:1]))) == TYPE_VALIDATOR) {
            // along with this validator initialization itself
            // for testing purposes
            SignerId signerId = SignerId.wrap(bytes32(data[1:33]));

            _enableSigner(
                signerId, //signerId
                address(bytes20(data[33:53])),      //signerValidator
                msg.sender,                         //smartAccount
                data[53:73]                         //signerData = 20bytes only for testing purposes, single EOA address
            );

            //enable couple of general permissions for the signerId
            uint256 numberOfUserOpPolicies = uint256(uint8(bytes1(data[73:74])));
            for(uint256 i; i < numberOfUserOpPolicies; i++) {
                // get address of the policy
                address policyAddress = address(bytes20(data[74 + i*(20+32): 94 + i*(20+32)]));
                bytes calldata policyData = data[94 + i*(20+32): 94+32 + i*(20+32)];
                //console2.log("Policy address: ", policyAddress);
                //console2.logBytes(policyData);
                _enableUserOpPolicy(signerId, policyAddress, msg.sender, policyData);
            }

            uint256 pointer = 74 + numberOfUserOpPolicies*(20+32);
            uint256 numberOfActionPolicies = uint256(uint8(bytes1(data[pointer:++pointer])));
            ActionId actionId = ActionId.wrap(bytes32(data[pointer:pointer+32]));
            //console2.log("ActionId submitted at onInstall");
            //console2.logBytes32(ActionId.unwrap(actionId));
            pointer += 32;
            for(uint256 i; i < numberOfActionPolicies; i++) {
                // get address of the policy
                address policyAddress = address(bytes20(data[pointer + i*(20+32): pointer+20 + i*(20+32)]));
                bytes calldata policyData = data[pointer+20 + i*(20+32): pointer+20+32 + i*(20+32)];
                //console2.log("Action Policy address: ", policyAddress);
                //console2.logBytes(policyData);
                _enableActionPolicy(signerId, actionId, policyAddress, msg.sender, policyData);
            }
            pointer += numberOfActionPolicies*(20+32);
            uint256 numberOf1271Policies = uint256(uint8(bytes1(data[pointer:++pointer])));
            for(uint256 i; i < numberOf1271Policies; i++) {
                // get address of the policy
                address policyAddress = address(bytes20(data[pointer + i*(20+32): pointer+20 + i*(20+32)]));
                bytes calldata policyData = data[pointer+20 + i*(20+32): pointer+20+32 + i*(20+32)];
                //console2.log("1271 Policy address: ", policyAddress);
                //console2.logBytes(policyData);
                _enableERC1271Policy(signerId, policyAddress, msg.sender, policyData);
            }
        }


        // TODO: 
        // make proper flow that uses the standard enable permissions routine
        // with the exception we do not need to check the signature here
        // as onInstall is only called by the SA itself => the call has already been authorized
        // _enablePermissions(__);
    }

    /**
     * De-initialize the module with the given data
     *
     * @param data The data to de-initialize the module with
     */
    function onUninstall(bytes calldata data) external override { }

    /**
     * Check if the module is initialized
     * @param smartAccount The smart account to check
     *
     * @return true if the module is initialized, false otherwise
     */
    function isInitialized(address smartAccount) external view returns (bool) {
        return true;
    }

    function _validateAndEnablePermissions(PackedUserOperation calldata userOp) 
        internal 
        returns (SignerId signerId, bytes calldata cleanSig, address signerValidator)
    {

        //(temp)
        // cleanSig = userOp.signature[33:];
        
        // 1. parse enableData and make enableDataHash
        
        console2.logBytes(userOp.signature);
        
        (
            uint8 permissionIndex,
            bytes calldata permissionEnableData,
            bytes calldata permissionEnableDataSignature,
            bytes calldata permissionData,
            bytes calldata userOpSig
        ) = _decodeEnableModeUserOpSignature(userOp.signature);
        
        /*
        console2.log("Permission Index: ", permissionIndex);
        console2.logBytes(permissionEnableData);
        console2.logBytes(permissionEnableDataSignature);
        console2.logBytes(permissionData);
        console2.logBytes(userOpSig);
        */

        // get chainId and permissionDataDigest from permissionEnableData with permissionIndex
        // check chainId 
        // make permissionDataDigest from permissionData and compare with permissionDataDigest obtained from permissionEnableData
        (
            uint64 permissionChainId,
            bytes32 permissionDigest
        ) = _parsePermissionFromPermissionEnableData(
                permissionEnableData,
                permissionIndex
            );

        if (permissionChainId != block.chainid) {
            revert("Permission Chain Id Mismatch");
        }

        bytes32 computedDigest = keccak256(permissionData);
        if (permissionDigest != computedDigest) {
            revert("PermissionDigest Mismatch");
        }

        /*
         2. check that it was properly signed
            what if the validator for this signerId is this module itself?
            it means anyone with 1271 permissions (as the scope for 1271 polices is very limited)
            will be able to enable any other permissions for themselves
            there are three solutions:
             - mark permissions enable data with magic value and revert in 1271 flow in this module if detected
             - make strong advise for users not to use 1271 permissions at all unless they 100% trust the dApp
             - always enable sender-based policies for 1271 permissions so it only validates if the isValidSignature 
                request has been sent by protocol. at least can restrict address(this) to be the sender. so at least
                it won't be possible to enable more permissions thru 1271
             - come up with a proper way of passing the correctly verified data about what has been signed from
                the Smart account to PermissionsValidator.isValidSignatureWithSender
        */

        _validatePermissionEnableDataSignature(
            msg.sender, //smartAccount
            keccak256(permissionEnableData), //hash of the permissionEnableData
            permissionEnableDataSignature
        );

        // 3. enable permissions 

        // (signerId, signerValidator) = _enablePermissions(permissionData);


        // can Enable Data be struct ideally to be able to sign it with 1271 properly?
        // no, it's gonna be dynamic bytes array

        // signer validator can also be obtained from enable data in many cases, saving one SLOAD
        // but if it was not the case (userOp was enabling only polciies, not the signer)
        // then we have to SLOAD it
        
        /*
        if (signerValidator == address(0)) {
            signerValidator = _permissionValidatorStorage().signers[signerId][msg.sender];
        }
        */
        cleanSig = userOpSig;
    }

    /*//////////////////////////////////////////////////////////////////////////
                            INTERNAL VALIDATION METHODS
    //////////////////////////////////////////////////////////////////////////*/

    function _validatePermissionEnableDataSignature(
        address smartAccount,
        bytes32 permissionEnableDataHash, 
        bytes calldata permissionEnableDataSignature
    ) internal view {
        if (
            IERC7579Account(smartAccount).isValidSignature(
                permissionEnableDataHash, 
                permissionEnableDataSignature
            ) != EIP1271_SUCCESS
        ) {
            revert("Permission Enable Sig invalid");
        } 
    }

    function _validate7579ExecuteCall(
        SignerId signerId,
        PackedUserOperation calldata userOp
    ) internal returns (ValidationData vd) {
        ExecutionMode mode = ExecutionMode.wrap(bytes32(userOp.callData[4:36]));

        // check if account supports execution mode that is in the userOp.callData
        if(!IAccountConfig(userOp.sender).supportsExecutionMode(mode)) {
            return VALIDATION_FAILED;
        }
        
        // first argument in userOp.callData is the execution mode (32 bytes)
        (CallType callType, ) = mode.decodeBasic();
        bytes calldata erc7579ExecutionCalldata = _clean7579ExecutionCalldata(userOp.callData);

        //console2.logBytes(erc7579ExecutionCalldata);
        
        if (callType == CALLTYPE_SINGLE) {
            (address target, uint256 value, bytes calldata actionCallData) = erc7579ExecutionCalldata.decodeSingle();
            vd = _validateSingleExecution(signerId, target, value, actionCallData, userOp);
        } else if (callType == CALLTYPE_BATCH) {
            (Execution[] calldata executions) = erc7579ExecutionCalldata.decodeBatch();
            for(uint256 i; i < executions.length; i++) {
                vd = vd.intersectValidationData(
                    _validateSingleExecution(
                        signerId, 
                        executions[i].target, 
                        executions[i].value, 
                        executions[i].callData, 
                        userOp
                    )
                );
            }           
        } else if (callType == CALLTYPE_DELEGATECALL) {
            vd = _validateSingleExecution(
                signerId, 
                address(uint160(bytes20(erc7579ExecutionCalldata[0:20]))), 
                0,
                erc7579ExecutionCalldata[20:], 
                userOp
            );
        }


        // if the execution mode is not known (some custom one),
        // then the solutions are:
        // a) revert
        // b) fallback to some handler 
        //    will have to think how to properly install/uninstall it on the account
        //    ideally via 7484 integration
    }

    function _validateSingleExecution(
        SignerId signerId,
        address target,
        uint256 value,
        bytes calldata data,
        PackedUserOperation calldata userOp
    ) 
    internal returns (ValidationData vd) 
    {    
        // if calldata is less than 4 bytes, consider this a value transfer
        // use ActionId = keccak(target, 0x00000000) for value transfers for a given target
        ActionId actionId = ActionId.wrap(keccak256(abi.encodePacked(
            target, 
            data.length >= 4 ? bytes4(data[0:4]) : bytes4(0)
        )));
        //console2.log("actionId detected at validation");
        //console2.logBytes32(ActionId.unwrap(actionId));

        AddressArray storage policies = _permissionValidatorStorage().actionPolicies[signerId][actionId][msg.sender];
        console2.log("action policies detected", policies.length());

        //get list of action policies and validate thru them
        vd = _validateActionPolicies(
            keccak256(abi.encodePacked(signerId, actionId)),
            policies,
            target,
            value,
            data, 
            userOp
        );
    }

    function _validateUserOpPolicies(
        SignerId signerId,
        AddressArray storage policies,
        PackedUserOperation calldata userOp
    ) internal returns (ValidationData vd) {
        for(uint256 i; i < policies.length(); i++) {
            console2.log("Validating UserOp Policy @ address: ", policies.get(i));
            vd = vd.intersectValidationData( 
                ValidationData.wrap(
                    uint256(bytes32(
                        _safeCallSubmoduleViaTrustedForwarder(
                            policies.get(i), 
                            abi.encodeWithSelector(
                                IUserOpPolicy.checkUserOp.selector, 
                                SignerId.unwrap(signerId), 
                                userOp
                            )
                        )
                    ))
                )
            ); 
        }
    }

    function _validateActionPolicies(
        bytes32 id,
        AddressArray storage policies,
        address target,
        uint256 value,
        bytes calldata data,
        PackedUserOperation calldata userOp
    ) internal returns (ValidationData vd) {
        for(uint256 i; i < policies.length(); i++) {
            console2.log("Validating Action Policy @ address: ", policies.get(i));
            vd = vd.intersectValidationData( 
                ValidationData.wrap(
                    uint256(bytes32(
                        _safeCallSubmoduleViaTrustedForwarder(
                            policies.get(i), 
                            abi.encodeWithSelector(
                                IActionPolicy.checkAction.selector, 
                                id, 
                                target, 
                                value, 
                                data, 
                                userOp
                            )
                        )
                    ))
                )
            ); 
        }
    }

    function _validateERC1271Policies(
        SignerId signerId,
        AddressArray storage policies,
        address sender,
        bytes32 hash,
        bytes calldata signature
    ) internal view returns (bytes4 sigValidationResult) {
        bytes32 id = keccak256(abi.encodePacked("ERC1271 Policy", SignerId.unwrap(signerId)));
        for(uint256 i; i < policies.length(); i++) {
            console2.log("Validating ERC1271 Policy @ address: ", policies.get(i));
            if(!I1271Policy(policies.get(i)).check1271SignedAction(id, msg.sender, sender, hash, signature)) {
                return EIP1271_FAILED;
            }
        }
        return EIP1271_SUCCESS;
    }

    function _safeCallSubmoduleViaTrustedForwarder(address submodule, bytes memory data) internal returns (bytes memory) {
        // if the submodule supports trusted forwarder, use it
        try IERC165(submodule).supportsInterface(type(ITrustedForwarder).interfaceId) returns (bool supported) {
            if(supported) {
                // call submodule via trusted forwarder
                return _callSubModuleAndHandleReturnData(
                    submodule, 
                    abi.encodePacked(
                        data,
                        address(this), //append self address
                        msg.sender   //append smart account address as original msg.sender
                    )
                );
            } else {
                return _callSubModuleAndHandleReturnData(submodule, data);
            }
        } catch (bytes memory /*error*/) {
            // sub-module doesn't support IERC165
            return _callSubModuleAndHandleReturnData(submodule, data);
            
        }
    }

    function _callSubModuleAndHandleReturnData(address submodule, bytes memory data) internal returns (bytes memory) {
        (bool success, bytes memory returnData) = submodule.call(data);
        if (!success) {
            // revert with the return data
            assembly {
                revert(add(returnData, 0x20), mload(returnData))
            }
        }
        return returnData;
    }

    function _clean7579ExecutionCalldata(bytes calldata userOpCallData) internal pure returns (bytes calldata erc7579ExecutionCalldata) {
        bytes calldata data  = userOpCallData;
        assembly {
            let baseOffset := add(data.offset, 0x24) //skip 4 bytes of selector and 32 bytes of execution mode
            erc7579ExecutionCalldata.offset := add(baseOffset, calldataload(baseOffset))
            erc7579ExecutionCalldata.length := calldataload(sub(erc7579ExecutionCalldata.offset, 0x20))
        }
    }

    /*//////////////////////////////////////////////////////////////////////////
                            INTERNAL CONFIGURATION METHODS
    //////////////////////////////////////////////////////////////////////////*/

    function _enableSigner(
        SignerId signerId, 
        address signerValidator, 
        address smartAccount, 
        bytes calldata signerData
    ) internal {   
        bytes memory _data = abi.encodePacked(signerId, signerData);

        // set signerValidator for signerId and smartAccount
        _permissionValidatorStorage().signers[signerId][smartAccount] = signerValidator;

        _initSubmodule(signerValidator, SignerId.unwrap(signerId), smartAccount, _data);
    }

    function _enableUserOpPolicy(
        SignerId signerId, 
        address userOpPolicy, 
        address smartAccount, 
        bytes calldata policyData
    ) internal {
        bytes memory _data = abi.encodePacked(signerId, policyData);

        AddressArray storage policies = _permissionValidatorStorage().userOpPolicies[signerId][smartAccount];
        _addPolicy(policies, userOpPolicy);

        _initSubmodule(userOpPolicy, SignerId.unwrap(signerId), smartAccount, _data);
    }

    function _enableActionPolicy(
        SignerId signerId, 
        ActionId actionId, 
        address actionPolicy, 
        address smartAccount, 
        bytes calldata policyData
    ) internal {
        AddressArray storage policies = _permissionValidatorStorage().actionPolicies[signerId][actionId][smartAccount];
        _addPolicy(policies, actionPolicy);

        bytes32 id = keccak256(abi.encodePacked(signerId, actionId));
        bytes memory _data = abi.encodePacked(id, policyData);
        _initSubmodule(actionPolicy, id, smartAccount, _data);
    }

    function _enableERC1271Policy(
        SignerId signerId, 
        address erc1271Policy, 
        address smartAccount, 
        bytes calldata policyData
    ) internal {
        AddressArray storage policies = _permissionValidatorStorage().erc1271Policies[signerId][smartAccount];
        _addPolicy(policies, erc1271Policy);

        bytes32 id = keccak256(abi.encodePacked("ERC1271 Policy", SignerId.unwrap(signerId)));
        bytes memory _data = abi.encodePacked(id, policyData);
        _initSubmodule(erc1271Policy, id, smartAccount, _data);
    }

    function _addPolicy(AddressArray storage policies, address policy) internal {            
        if(!policies.contains(policy)) {
            policies.push(policy);
            //console2.log("check from storage: ", _permissionValidatorStorage().userOpPolicies[signerId][smartAccount].data[policies.lastUsedIndex()]);
        } else {
            // same policy can not be used twice for the same signerId and smartAccount, as
            // inside the policy contract the config is stored as signerId=>smartAccount=>config
            revert PolicyAlreadyUsed(policy);
        }
    }

    function _initSubmodule( 
        address subModule, 
        bytes32 id,
        address smartAccount, 
        bytes memory subModuleInitData
    ) internal {
        try IERC165(subModule).supportsInterface(type(ITrustedForwarder).interfaceId) returns (bool supported) {
            if(supported) {
                // set trusted forwarder via SA
                // This module SHOULD be installed as an executor on the smart account
                // to be able to call executeFromExecutor
                // The if check allows to avoid excess sstore's in case sub-module uses id-less approach
                if(!ITrustedForwarder(subModule).isTrustedForwarder(address(this), smartAccount, id)) {
                    _execute(
                        smartAccount, 
                        subModule,
                        0, 
                        abi.encodeWithSelector(ITrustedForwarder.setTrustedForwarder.selector, address(this), id)
                    );
                }
                
                // configure submodule via trusted forwarder
                (bool success, ) = subModule.call(
                    abi.encodePacked(
                        abi.encodeCall(IERC7579Module.onInstall, (subModuleInitData)),
                        address(this), //append self address
                        smartAccount   //append smart account address as original msg.sender
                    )
                );
                if (!success) revert();
            } else {
                // sub-module doesn't support trusted forwarder
                // so it doesn't use msg.sender except in onInstall
                // so we can just do onInstall via executeFromExecutor
                _execute(
                    smartAccount, 
                    subModule,
                    0, 
                    abi.encodeWithSelector(IERC7579Module.onInstall.selector, subModuleInitData)
                );
            }
        } catch (bytes memory /*error*/) {
            // sub-module doesn't support trusted forwarder
            _execute(
                smartAccount, 
                subModule,
                0, 
                abi.encodeWithSelector(IERC7579Module.onInstall.selector, subModuleInitData)
            );
        }
    }

    function _isEnableMode(bytes calldata signature) internal pure returns (bool) {
        return signature[0] == 0x01;
    }

    function _decodeEnableModeUserOpSignature(bytes calldata signature) internal pure returns (
        uint8 permissionIndex,
        bytes calldata permissionEnableData,
        bytes calldata permissionEnableDataSignature,
        bytes calldata permissionData,
        bytes calldata cleanSig
    ) {
        permissionIndex = uint8(signature[1]);
        /*
        0x
        01 // enable mode flag
        01 // permissionIndex
        0000000000000000000000000000000000000000000000000000000000000080 // permissionEnableData offset
        00000000000000000000000000000000000000000000000000000000000000a0 // permissionEnableDataSignature offset
        00000000000000000000000000000000000000000000000000000000000000c0 // permissionData offset
        0000000000000000000000000000000000000000000000000000000000000280 // cleanSigOffset
        0000000000000000000000000000000000000000000000000000000000000000 // permissionEnableData
        0000000000000000000000000000000000000000000000000000000000000000 // permissionEnableDataSignature
        0000000000000000000000000000000000000000000000000000000000000188 // permissionData length
        === permissionData ==
        5d5f7ea3a5cc54ab2b29951ab1b6fe12b49f67d9b348a0db68eca805921e4c58 // signer, 32
        01020201 // descriptor , 4
        15cf58144ef33af1e14b5208015d11f9143e27b9 // signer validator address , 20
        00000014 // signer validator data length , 4
        db1a3d8defd683eaa1e2b99613917c6264571f1a212224d2f2d262cd093ee13240ca4873fccbba3c00000020000000000000000000000000000000000000000000000000000000000000000a2a07706473244bc757e10f2a9e86fb532828afe300000020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc92773bb6d2f7693a7561aaf3c2e3f3d161b7b70e085358ac9ed27b74ad45a46212224d2f2d262cd093ee13240ca4873fccbba3c0000002000000000000000000000000000000000000000000000000000000000000000053d7ebc40af7092e3f1c81f2e996cba5cae2090d70000002000000000000000000000000064262668000000000000000000000000642622803d7ebc40af7092e3f1c81f2e996cba5cae2090d70000002000000000000000000000000064264de700000000000000000000000064262474000000000000000000000000000000000000000000000000
        0000000000000000000000000000000000000000000000000000000000000041
        b808a9184de43655b2ff55ac5049e6c94824c4caa792d549c3987a386954d7ca2c2038f87b3569b5d80a005f7f9e3b0504b18af13e2bc5a83b1de9207da4143d1b00000000000000000000000000000000000000000000000000000000000000
        */

        assembly {
            let baseOffset := add(signature.offset, 0x02)
            let offset := baseOffset
            
            // get permissionEnableData
            let dataPointer := add(baseOffset, calldataload(offset))
            permissionEnableData.offset := add(0x20, dataPointer)
            permissionEnableData.length := calldataload(dataPointer)

            // get permissionEnableDataSignature
            offset := add(offset, 0x20)
            dataPointer := add(baseOffset, calldataload(offset))
            permissionEnableDataSignature.offset := add(0x20, dataPointer)
            permissionEnableDataSignature.length := calldataload(dataPointer)

            // get permissionData
            offset := add(offset, 0x20)
            dataPointer := add(baseOffset, calldataload(offset))
            permissionData.offset := add(0x20, dataPointer)
            permissionData.length := calldataload(dataPointer)

            // get cleanSig
            offset := add(offset, 0x20)
            dataPointer := add(baseOffset, calldataload(offset))
            cleanSig.offset := add(0x20, dataPointer)
            cleanSig.length := calldataload(dataPointer)
        }
    }

    function _parsePermissionFromPermissionEnableData(
        bytes calldata permissionEnableData, 
        uint8 permissionIndex
    ) internal view returns (uint64 permissionChainId, bytes32 permissionDigest) {
        assembly {
            let baseOffset := permissionEnableData.offset
            let offset := add(baseOffset, mul(40, permissionIndex))
            permissionChainId := shr(
                192,
                calldataload(offset)
            )
            permissionDigest := calldataload(add(offset, 8))
        }
        console2.log(permissionChainId);
        console2.logBytes32(permissionDigest);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     PUBLIC INTERFACE
    //////////////////////////////////////////////////////////////////////////*/

    // signerId can be enabled counterfactually, when enable data has been signed
    // but not submitted to the chain yet
    function isSignerIdEnabledOnchain(bytes32 signerId, address smartAccount) external view returns (bool) {
        return _permissionValidatorStorage().signers[SignerId.wrap(signerId)][smartAccount] != address(0);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     METADATA
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * The name of the module
     *
     * @return name The name of the module
     */
    function name() external pure returns (string memory) {
        return "ValidatorTemplate";
    }

    /**
     * The version of the module
     *
     * @return version The version of the module
     */
    function version() external pure returns (string memory) {
        return "0.0.1";
    }

    /**
     * Check if the module is of a certain type
     *
     * @param typeID The type ID to check
     *
     * @return true if the module is of the given type, false otherwise
     */
    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == TYPE_VALIDATOR || typeID == TYPE_EXECUTOR;
    }
}
