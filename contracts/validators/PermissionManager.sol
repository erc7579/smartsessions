// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { ERC7579ValidatorBase, ERC7579ExecutorBase } from "modulekit/Modules.sol";
import { PackedUserOperation } from "modulekit/external/ERC4337.sol";
import { AddressArray, AddressArrayLib } from "contracts/utils/lib/AddressArrayLib.sol";
import { ModeLib, ExecutionMode, ExecType, CallType, CALLTYPE_BATCH, CALLTYPE_SINGLE, CALLTYPE_STATIC, CALLTYPE_DELEGATECALL, EXECTYPE_DEFAULT, EXECTYPE_TRY } from "contracts/utils/lib/ModeLib.sol";
import { ExecutionLib } from "erc7579/lib/ExecutionLib.sol";
import { ValidationDataLib } from "contracts/utils/lib/ValidationDataLib.sol";
import { PermissionDescriptor, PermissionDescriptorLib } from "contracts/utils/lib/PermissionDescriptorLib.sol";
import { NonceMixinLib } from "contracts/utils/lib/NonceMixinLib.sol";

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
    - Renounce policies and signers
        - what do we do with isInitialized in sub-modules if we bulk renounce submodules in the Permission Manager
        without calling onUninstall on every sub-module. Probably need to introduce same nonce system for submodules as well
        we need to make no hidden enabled configs are left in sub-modules
        Also need to disable trustedForwarder config for given SA 
        but how do we get all the submodules used for given SA, while indexing is by SignerIds. the only way is storing 
        signerIds list for givenSA but this is extremely inefficient
        Should we allow bulk disabling in this case at all? 
        How do we disable the whole signerId in case it is compromised?

    - isInitialized for SA (just takes the length of the signerId's array stored at keccak(p))
    - Permissions hook (soending limits?)
    - Check Policies/Signers via Registry before enabling
    - In policies contracts, change signerId to id



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
    using PermissionDescriptorLib for PermissionDescriptor;
    using NonceMixinLib for bytes32;

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

        mapping(address => mapping (bytes32 => bool)) renouncedPermissionEnableObjects;
        
        mapping (address => uint256) nonces;
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
        //        optimized this so, when the signer validator is available from enable data,
        //        we take it from there and return to validation flow

        SignerId signerId;
        bytes calldata cleanSig;
        address signerValidator;

        // if this is enable mode, we know the signerValidator from it
        // otherwise we get the signerValidator from the storage
        if(_isEnableMode(userOp.signature)) {
            console2.log("Enable Mode activated");
            (signerId, cleanSig, signerValidator) = _validateAndEnablePermissions(userOp);
        } else {
            signerId = SignerId.wrap(
                (bytes32(userOp.signature[1:33])).mixinNonce(_permissionValidatorStorage().nonces[msg.sender])
            );
            cleanSig = userOp.signature[33:];
            signerValidator = _permissionValidatorStorage().signers[signerId][msg.sender];
        }

        /**  
         *  Check signature and policies
         */

        if (ISignerValidator(signerValidator).checkSignature(SignerId.unwrap(signerId), msg.sender, userOpHash, cleanSig) == EIP1271_FAILED) {
            console2.log("wrong signature");
            return VALIDATION_FAILED;
        }
        console2.log("Signature validation at ISignerValidator.checkSignature passed");

        // Check userOp level Policies
        AddressArray storage policies = _permissionValidatorStorage().userOpPolicies[signerId][msg.sender];
        vd = _validateUserOpPolicies(signerId, policies, userOp);
        console2.log("UserOp Policies verification passed");

        // Check action policies
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
        SignerId signerId = SignerId.wrap(
            (bytes32(signature[1:33])).mixinNonce(_permissionValidatorStorage().nonces[msg.sender])
        );
        bytes memory cleanSig = signature[33:];
        address signerValidator = _permissionValidatorStorage().signers[signerId][msg.sender];
        
        // in some cases we do not need signer validation, 
        // in this case NO_SIGNATURE_VALIDATION_REQUIRED should be stored as signer validator for such signer id
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
        // since it is view, can safely introduce policies based on sender (blacklist/whitelist senders etc)
        // it will be SA's job to ensure it passes correct sender, otherwise it will be unsafe for SA itself
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
        //if this module is being installed as a validator
        if(uint256(uint8(bytes1(data[:1]))) == TYPE_VALIDATOR) {
            _enablePermission(data[1:]);
        }
    }

    /**
     * De-initialize the module with the given data
     *
     * @param data The data to de-initialize the module with
     */
    function onUninstall(bytes calldata data) external override {
        resetModule();
    }

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
        returns (SignerId, bytes calldata, address)
    {        
        // 1. parse enableData and make enableDataHash
        (
            uint8 permissionIndex,
            bytes calldata permissionEnableData,
            bytes calldata permissionEnableDataSignature,
            bytes calldata permissionData,
            bytes calldata cleanSig
        ) = _decodeEnableModeUserOpSignature(userOp.signature);
        
        // 2. get chainId and permissionDataDigest from permissionEnableData with permissionIndex
        // check chainId 
        // make permissionDataDigest from permissionData and compare with permissionDataDigest obtained from permissionEnableData
        {
            (
                uint64 permissionChainId,
                bytes32 permissionDigest
            ) = _parsePermissionFromPermissionEnableData(
                    permissionEnableData,
                    permissionIndex
                );
            
            // check that this enable object has not been banned before being enabled
            bytes32 permissionEnableObject = keccak256(abi.encodePacked(permissionChainId, permissionDigest));
            if(_permissionValidatorStorage().renouncedPermissionEnableObjects[msg.sender][permissionEnableObject]) {
                revert("Object has been renounced");
            }

            if (permissionChainId != block.chainid) {
                revert("Permission Chain Id Mismatch");
            }

            bytes32 computedDigest = keccak256(permissionData);
            if (permissionDigest != computedDigest) {
                revert("PermissionDigest Mismatch");
            }
        }

        /*
         3. check that it was properly signed
            what if the validator for this signerId is this module itself?
            it means anyone with 1271 permissions (as the scope for 1271 polices is very limited)
            will be able to enable any other permissions for themselves
            there are three solutions:
             - mark permissions enable data with magic value and revert in 1271 flow in this module if detected
             - make strong advise for users not to use 1271 permissions at all unless they 100% trust the dApp
             - always enable sender-based policies for 1271 permissions so it only validates if the isValidSignature 
                request has been sent by protocol. at least can restrict address(this) to be the sender. 
                so at least it won't be possible to enable more permissions thru 1271 
                Using this approach currently => see isValidSignatureWithSender method
             - come up with a proper way of passing the correctly verified data about what has been signed from
                the Smart account to PermissionsValidator.isValidSignatureWithSender
        */
        _validatePermissionEnableDataSignature(
            msg.sender, //smartAccount
            keccak256(permissionEnableData), //hash of the permissionEnableData
            permissionEnableDataSignature
        );
        
        console2.log("permission enable sig validated successfully");

        // 4. enable permissions 
        (SignerId signerId, address signerValidator) = _enablePermission(permissionData);
        console2.log("permissions enabled");


        // signer validator can be obtained from enable data in many cases, saving one SLOAD
        // but if it was not the case (userOp was enabling only policies, not the signer)
        // then we have to SLOAD it
        if (signerValidator == address(0)) {
            signerValidator = _permissionValidatorStorage().signers[signerId][msg.sender];
        }
        
        return(signerId, cleanSig, signerValidator);
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

        (CallType callType, ) = mode.decodeBasic();
        bytes calldata erc7579ExecutionCalldata = _clean7579ExecutionCalldata(userOp.callData);
        
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


        // TODO: if the execution mode is not known (some custom one),
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
        // TODO: test it
        ActionId actionId = ActionId.wrap(keccak256(abi.encodePacked(
            target, 
            data.length >= 4 ? bytes4(data[0:4]) : bytes4(0)
        )));

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
            // same policy can not be used twice as the policy of the sane type (userOp, action, 1271)
            // for the same id and smartAccount, as inside the policy contract the config is stored as id=>smartAccount=>config
            // so same policy can be used as 1271 and userOp and action for the same SA, as ids will be different
            // also same policy can be used several times as action policy for the same signerId and SA, as soon as it is used
            // with different actionIds (contract + selector)
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
            // sub-module doesn't support IERC165 => it doesn't support trusted forwarder => see above
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
            // 40 = chainId (8bytes) + digest (32 bytes)
            let offset := add(baseOffset, mul(40, permissionIndex))
            permissionChainId := shr(
                192,
                calldataload(offset)
            )
            permissionDigest := calldataload(add(offset, 8))
        }
    }

    function _enablePermission(bytes calldata permissionData) internal returns (SignerId, address) {

        SignerId signerId = SignerId.wrap(
            bytes32(permissionData[0:32]).mixinNonce(_permissionValidatorStorage().nonces[msg.sender])
        );
        
        PermissionDescriptor permissionDescriptor = PermissionDescriptor.wrap(bytes4(permissionData[32:36]));
        console2.logBytes4(PermissionDescriptor.unwrap(permissionDescriptor));

        uint256 offset = 36;

        address signerValidator;
        uint256 addOffset;
        
        // enable signer if required
        if(permissionDescriptor.isSignerEnableMode()) {
            (addOffset, signerValidator) = _parseAndEnableSigner(signerId, permissionData[offset:]);
            offset += addOffset;
        }
        console2.log("offset fter enabl signer ", offset);

        // enable userOp policies
        offset += _parseAndEnableUserOpPolicies(signerId, permissionDescriptor, permissionData[offset:]);

        // enable action policies
        offset += _parseAndEnableActionPolicies(signerId, permissionDescriptor, permissionData[offset:]);

        // enable 1271 policies
        _parseAndEnable1271Policies(signerId, permissionDescriptor, permissionData[offset:]);

        return(signerId, signerValidator);
    }

    function _parseAndEnableSigner(SignerId signerId, bytes calldata permissionData) 
        internal  
        returns (uint256 addOffset, address signerValidator) 
    {
        signerValidator = address(uint160(bytes20(permissionData[0:20])));
        uint32 dataLength = uint32(bytes4(permissionData[20:24]));
        console2.log(dataLength);
        bytes calldata signerValidatorConfigureData = permissionData[24:24+dataLength];
        _enableSigner(
                signerId,
                signerValidator,
                msg.sender, //smartAccount
                signerValidatorConfigureData        
            );
        addOffset = 24 + dataLength;
    }

    function _parseAndEnableUserOpPolicies(
        SignerId signerId, 
        PermissionDescriptor permissionDescriptor,
        bytes calldata permissionData
    ) internal returns (uint256 addOffset) {
        uint256 numberOfPolicies = permissionDescriptor.getUserOpPoliciesNumber();
        console2.log("num of userOp policies ", numberOfPolicies);
        for (uint256 i; i<numberOfPolicies; i++) {
            (address userOpPolicy, bytes calldata policyData) = _parsePolicy(permissionData[addOffset:]);
            addOffset += 24+policyData.length;
            _enableUserOpPolicy(signerId, userOpPolicy, msg.sender, policyData);
        }
    }

    function _parseAndEnableActionPolicies(
        SignerId signerId, 
        PermissionDescriptor permissionDescriptor,
        bytes calldata permissionData
    ) internal returns (uint256) {
        uint256 numberOfPolicies = permissionDescriptor.getActionPoliciesNumber();
        ActionId actionId = ActionId.wrap(bytes32(permissionData[0:32]));
        uint256 addOffset = 32;
        console2.log("num of action policies ", numberOfPolicies);
        for (uint256 i; i<numberOfPolicies; i++) {
            (address actionPolicy, bytes calldata policyData) = _parsePolicy(permissionData[addOffset:]);
            addOffset += 24+policyData.length;
            _enableActionPolicy(signerId, actionId, actionPolicy, msg.sender, policyData);
        }
        return addOffset;
    }

    function _parseAndEnable1271Policies(
        SignerId signerId, 
        PermissionDescriptor permissionDescriptor,
        bytes calldata permissionData
    ) internal returns (uint256 addOffset) {
        uint256 numberOfPolicies = permissionDescriptor.get1271PoliciesNumber();
        console2.log("num of 1271 policies ", numberOfPolicies);
        for (uint256 i; i<numberOfPolicies; i++) {
            (address erc1271Policy, bytes calldata policyData) = _parsePolicy(permissionData[addOffset:]);
            addOffset += 24+policyData.length;
            _enableERC1271Policy(signerId, erc1271Policy, msg.sender, policyData);
        }
    }

    function _parsePolicy(bytes calldata partialPermissionData) internal pure returns (address policy, bytes calldata policyData) {
        policy = address(uint160(bytes20(partialPermissionData[0:20])));
        console2.log("Enabling policy ", policy);
        uint256 dataLength = uint256(uint32(bytes4(partialPermissionData[20:24])));
        policyData = partialPermissionData[24:24+dataLength];
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     RENOUNCE METHODS
    //////////////////////////////////////////////////////////////////////////*/

    /** 
     * @dev Makes all the signerIds in storage effectively unreachable
     * by incrementing the nonce that is mixed into the signerId
    */
    function resetModule() public {
        _permissionValidatorStorage().nonces[msg.sender]++;
    }

    function renounceUserOpPolicy(SignerId signerId, address policy) external {
        _permissionValidatorStorage().userOpPolicies[signerId][msg.sender].removeElement(policy);
        _safeCallSubmoduleViaTrustedForwarder(
                            policy, 
                            abi.encodeWithSelector(
                                IERC7579Module.onUninstall.selector, 
                                abi.encodePacked(SignerId.unwrap(signerId))
                            )
                        );
    }


    function renounceActionPolicy(SignerId signerId, ActionId actionId, address policy) external {

    }

    function renounce1271Policy(SignerId signerId, address policy) external {

    }

    /** 
     * @dev Allows to renounce the permission that has not even been enabled on-chain.
     * It does it by marking the permission enable object that have been signed as renounced
     *
    */
    function renouncePermissionEnableObject(uint64 chainId, bytes32 permissionDigest) public {
        bytes32 permissionEnableObject = keccak256(abi.encodePacked(chainId, permissionDigest));
        _permissionValidatorStorage().renouncedPermissionEnableObjects[msg.sender][permissionEnableObject] = true;
    }



    /*//////////////////////////////////////////////////////////////////////////
                                     PUBLIC INTERFACE
    //////////////////////////////////////////////////////////////////////////*/

    // signerId can be enabled counterfactually, when enable data has been signed
    // but not submitted to the chain yet
    function isSignerIdEnabledOnchain(bytes32 _signerId, address smartAccount) external view returns (bool) {
        uint256 nonce = _permissionValidatorStorage().nonces[smartAccount];
        SignerId signerId = SignerId.wrap(_signerId.mixinNonce(nonce));
        return _permissionValidatorStorage().signers[signerId][smartAccount] != address(0);
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
