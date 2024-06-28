// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { ERC7579ValidatorBase, ERC7579ExecutorBase } from "modulekit/Modules.sol";
import { PackedUserOperation } from "modulekit/external/ERC4337.sol";
import { ModeLib, ExecutionMode, ExecType, CallType, CALLTYPE_BATCH, CALLTYPE_SINGLE, CALLTYPE_STATIC, CALLTYPE_DELEGATECALL, EXECTYPE_DEFAULT, EXECTYPE_TRY } from "contracts/utils/lib/ModeLib.sol";
import { ExecutionLib } from "erc7579/lib/ExecutionLib.sol";
import { ValidationDataLib } from "contracts/utils/lib/ValidationDataLib.sol";
import { PermissionDescriptor, PermissionDescriptorLib } from "contracts/utils/lib/PermissionDescriptorLib.sol";
import { NonceMixinLib } from "contracts/utils/lib/NonceMixinLib.sol";

import { IPermissionManager, NO_SIGNATURE_VALIDATION_REQUIRED } from "contracts/interfaces/validators/IPermissionManager.sol";
import { IERC7579Account, Execution } from  "erc7579/interfaces/IERC7579Account.sol";
import { IModule as IERC7579Module } from "erc7579/interfaces/IERC7579Module.sol";
import { IAccountExecute} from "modulekit/external/ERC4337.sol";
import { ISignerValidator } from "contracts/interfaces/ISignerValidator.sol";
import { ITrustedForwarder } from "contracts/utils/interfaces/ITrustedForwarder.sol";
import { IUserOpPolicy, IActionPolicy, I1271Policy } from "contracts/interfaces/IPolicies.sol";
import { IAccountConfig } from "contracts/utils/interfaces/IAccountConfig.sol";
import { IERC165 } from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import { AddressArrayMap4337, Bytes32ArrayMap4337, ArrayMap4337Lib } from "contracts/utils/lib/ArrayMap4337Lib.sol";

import "forge-std/console2.sol";

interface IPermissionEnabled {
    function isPermissionEnabled(bytes calldata data, address smartAccount) external view returns (bool, bytes32);
}

/**
TODO:
    - Renounce policies and signers
        - disable trustedForwarder config for given SA !!!
    - Permissions hook (soending limits?)
    - Check Policies/Signers via Registry before enabling
    - In policies contracts, change signerId to id
 */

contract PermissionManager is ERC7579ValidatorBase, ERC7579ExecutorBase, IPermissionManager, IPermissionEnabled {
    /*//////////////////////////////////////////////////////////////////////////
                            CONSTANTS & STORAGE
    //////////////////////////////////////////////////////////////////////////*/

    // bytes32(uint256(keccak256('erc7579.module.permissionvalidator')) - 1)
    bytes32 constant PERMISSION_VALIDATOR_STORAGE_SLOT = 0x73a9885e8be4b58095971868aa2af983b5913f3e08c5b78a3ca0cb6b827458f8;

    using ExecutionLib for bytes;
    using ModeLib for ExecutionMode;
    using ValidationDataLib for ValidationData;
    using PermissionDescriptorLib for PermissionDescriptor;
    using NonceMixinLib for bytes32;
    using ArrayMap4337Lib for Bytes32ArrayMap4337;
    using ArrayMap4337Lib for AddressArrayMap4337;

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
        

    // TODO: just a random seed => need to recalculate?
    // signerValidators mapping
    uint256 private constant _SIGNER_VALIDATORS_SLOT_SEED = 0x5a8d4c29;
    uint256 private constant _RENOUNCED_PERMISSIONS_SLOT_SEED = 0xa8cc43e2;
    uint256 private constant _NONCES_SLOT_SEED = 0xfcc720b6;

    mapping (SignerId => AddressArrayMap4337) userOpPolicies;
    mapping(SignerId => mapping (ActionId => AddressArrayMap4337)) actionPolicies;  
    mapping(SignerId => AddressArrayMap4337) erc1271Policies;
    mapping(SignerId => Bytes32ArrayMap4337) enabledActionIds;
    Bytes32ArrayMap4337 enabledSignerIds;

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
                (bytes32(userOp.signature[1:33])).mixinNonce(getNonce(msg.sender))
            );
            cleanSig = userOp.signature[33:];
            signerValidator = getSignerValidator(signerId, msg.sender);
            if(signerValidator == address(0)) {
                revert SignerIdNotEnabled(SignerId.unwrap(signerId));
            }
        }

        /**  
         *  Check signature and policies
         */
        if (signerValidator != NO_SIGNATURE_VALIDATION_REQUIRED) {
            if (ISignerValidator(signerValidator).checkSignature(SignerId.unwrap(signerId), msg.sender, userOpHash, cleanSig) == EIP1271_FAILED) {
                console2.log("wrong signature");
                return VALIDATION_FAILED;
            }
        }
        console2.log("Signature validation at ISignerValidator.checkSignature passed");

        // Check userOp level Policies
        // AddressArray storage policies = _permissionValidatorStorage().userOpPolicies[signerId][msg.sender];
        vd = _validateUserOpPolicies(signerId, msg.sender, userOp);
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
            (bytes32(signature[1:33])).mixinNonce(getNonce(msg.sender))
        );
        bytes memory cleanSig = signature[33:];
        address signerValidator = getSignerValidator(signerId, msg.sender);
        
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
        return _validateERC1271Policies(signerId, msg.sender, sender, hash, signature);
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
        return enabledSignerIds.length(smartAccount) != 0;
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
        ) = _decodeEnableModePackedData(userOp.signature[1:]);
        
        // 2. get chainId and permissionDataDigest from permissionEnableData with permissionIndex
        // check chainId 
        // make permissionDataDigest from permissionData and compare with permissionDataDigest obtained from permissionEnableData
        _validatePermissionEnableData(permissionIndex, permissionEnableData, permissionData);

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
            signerValidator = getSignerValidator(signerId, msg.sender);
        }
        
        return(signerId, cleanSig, signerValidator);
    }

    /*//////////////////////////////////////////////////////////////////////////
                            INTERNAL VALIDATION METHODS
    //////////////////////////////////////////////////////////////////////////*/

    function _validatePermission(address smartAccount, bytes calldata data) internal view returns (bytes calldata) {
        (
            uint8 permissionIndex,
            bytes calldata permissionEnableData,
            bytes calldata permissionEnableDataSignature,
            bytes calldata permissionData,
             
        ) = _decodeEnableModePackedData(data);

        _validatePermissionEnableData(permissionIndex, permissionEnableData, permissionData);

        _validatePermissionEnableDataSignature(
            smartAccount,
            keccak256(permissionEnableData), //hash of the permissionEnableData
            permissionEnableDataSignature
        );

        return permissionData;
    }

    function _validatePermissionEnableData(
        uint8 permissionIndex, 
        bytes calldata permissionEnableData, 
        bytes calldata permissionData
    ) internal view {
            (
                uint64 permissionChainId,
                bytes32 permissionDigest
            ) = _parsePermissionFromPermissionEnableData(
                    permissionEnableData,
                    permissionIndex
                );
            
            // check that this enable object has not been banned before being enabled
            bytes32 permissionEnableObject = keccak256(abi.encodePacked(permissionChainId, permissionDigest));
            if(isPermissionObjectRenounced(permissionEnableObject, msg.sender)) {
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

        //get list of action policies and validate thru them
        vd = _validateActionPolicies(
            signerId,
            actionId,
            msg.sender,
            target,
            value,
            data, 
            userOp
        );
    }

    function _validateUserOpPolicies(
        SignerId signerId,
        address smartAccount,
        PackedUserOperation calldata userOp
    ) internal returns (ValidationData vd) {
        AddressArrayMap4337 storage policies = userOpPolicies[signerId];
        for(uint256 i; i < policies.length(smartAccount); i++) {
            console2.log("Validating UserOp Policy @ address: ", policies.get(smartAccount, i));
            vd = vd.intersectValidationData( 
                ValidationData.wrap(
                    uint256(bytes32(
                        _callSubModuleAndHandleReturnData(
                            policies.get(smartAccount, i), 
                            abi.encodePacked(
                                abi.encodeWithSelector(
                                    IUserOpPolicy.checkUserOp.selector, 
                                    SignerId.unwrap(signerId), 
                                    userOp
                                ),
                                address(this), //append self address
                                smartAccount   //append smart account address as original msg.sender
                            )
                        )
                    ))
                )
            ); 
        }
    }

    function _validateActionPolicies(
        SignerId signerId,
        ActionId actionId,
        address smartAccount,
        address target,
        uint256 value,
        bytes calldata data,
        PackedUserOperation calldata userOp
    ) internal returns (ValidationData vd) {

        AddressArrayMap4337 storage policies = actionPolicies[signerId][actionId];
        console2.log("action policies detected", policies.length(smartAccount));

        for(uint256 i; i < policies.length(smartAccount); i++) {
            console2.log("Validating Action Policy @ address: ", policies.get(smartAccount, i));
            vd = vd.intersectValidationData( 
                ValidationData.wrap(
                    uint256(bytes32(
                        _callSubModuleAndHandleReturnData(
                            policies.get(smartAccount, i), 
                            abi.encodePacked(
                                abi.encodeWithSelector(
                                    IActionPolicy.checkAction.selector, 
                                    keccak256(abi.encodePacked(signerId, actionId)),  //id
                                    target, 
                                    value, 
                                    data, 
                                    userOp
                                ),
                                address(this), //append self address
                                smartAccount   //append smart account address as original msg.sender
                            )
                        )
                    ))
                )
            ); 
        }
    }

    function _validateERC1271Policies(
        SignerId signerId,
        address smartAccount,
        address sender,
        bytes32 hash,
        bytes calldata signature
    ) internal view returns (bytes4 sigValidationResult) {
        AddressArrayMap4337 storage policies = erc1271Policies[signerId];
        bytes32 id = keccak256(abi.encodePacked("ERC1271 Policy", SignerId.unwrap(signerId)));
        for(uint256 i; i < policies.length(smartAccount); i++) {
            console2.log("Validating ERC1271 Policy @ address: ", policies.get(smartAccount, i));
            if(!I1271Policy(policies.get(smartAccount, i)).check1271SignedAction(id, msg.sender, sender, hash, signature)) {
                return EIP1271_FAILED;
            }
        }
        return EIP1271_SUCCESS;
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
        _setSignerValidator(signerId, smartAccount, signerValidator);
        enabledSignerIds.push(smartAccount, SignerId.unwrap(signerId));
        _initSubmodule(signerValidator, SignerId.unwrap(signerId), smartAccount, _data);
    }

    function _enableUserOpPolicy(
        SignerId signerId, 
        address userOpPolicy, 
        address smartAccount, 
        bytes calldata policyData
    ) internal {
        AddressArrayMap4337 storage policies = userOpPolicies[signerId];
        _addPolicy(policies, smartAccount, userOpPolicy);

        bytes memory _data = abi.encodePacked(signerId, policyData);
        _initSubmodule(userOpPolicy, SignerId.unwrap(signerId), smartAccount, _data);
    }

    function _enableActionPolicy(
        SignerId signerId, 
        ActionId actionId, 
        address actionPolicy, 
        address smartAccount, 
        bytes calldata policyData
    ) internal {
        AddressArrayMap4337 storage policies = actionPolicies[signerId][actionId];
        _addPolicy(policies, smartAccount, actionPolicy);

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
        AddressArrayMap4337 storage policies = erc1271Policies[signerId];
        _addPolicy(policies, smartAccount, erc1271Policy);

        bytes32 id = keccak256(abi.encodePacked("ERC1271 Policy", SignerId.unwrap(signerId)));
        bytes memory _data = abi.encodePacked(id, policyData);
        _initSubmodule(erc1271Policy, id, smartAccount, _data);
    }

    function _addPolicy(AddressArrayMap4337 storage policies, address smartAccount, address policy) internal {            
        if(!policies.contains(smartAccount, policy)) {
            policies.push(smartAccount, policy);
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

    function _decodeEnableModePackedData(bytes calldata packedData) internal pure returns (
        uint8 permissionIndex,
        bytes calldata permissionEnableData,
        bytes calldata permissionEnableDataSignature,
        bytes calldata permissionData,
        bytes calldata cleanSig
    ) {
        permissionIndex = uint8(packedData[0]);

        assembly {
            let baseOffset := add(packedData.offset, 0x01)
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
            bytes32(permissionData[0:32]).mixinNonce(getNonce(msg.sender))
        );
        
        PermissionDescriptor permissionDescriptor = PermissionDescriptor.wrap(bytes4(permissionData[32:36]));
        console2.logBytes4(PermissionDescriptor.unwrap(permissionDescriptor));

        uint256 offset = 36;

        address signerValidator;
        uint256 addOffset;
        bytes calldata signerValidatorConfigureData;
        
        // enable signer if required
        if(permissionDescriptor.isSignerEnableMode()) {
            // if signerId already enabled, can not re-enable it. should use changeSignerValidator
            if(getSignerValidator(signerId, msg.sender) != address(0)) {
                revert SignerIdAlreadyEnabled(SignerId.unwrap(signerId));
            } 
            (addOffset, signerValidator, signerValidatorConfigureData) = _parseSigner(permissionData[offset:]);
            offset += addOffset;
            _enableSigner(
                signerId,
                signerValidator,
                msg.sender, //smartAccount
                signerValidatorConfigureData        
            );
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

    function _parseSigner(bytes calldata data) 
        internal view 
        returns (uint256 addOffset, address signerValidator, bytes calldata signerValidatorConfigureData) 
    {   
        if(data.length < 24) {
            revert("Wrong signerId enable data");
        }
        signerValidator = address(uint160(bytes20(data[0:20])));
        if (signerValidator == address(0)) {
            revert();
        }
        uint32 dataLength = uint32(bytes4(data[20:24]));

        signerValidatorConfigureData = data[24:24+dataLength];
       
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
        if(numberOfPolicies != 0) {
            Bytes32ArrayMap4337 storage actionIds = enabledActionIds[signerId];
            if(!actionIds.contains(msg.sender, ActionId.unwrap(actionId))) {
                actionIds.push(msg.sender, ActionId.unwrap(actionId));
            }
        }
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
        address smartAccount = msg.sender;
        incrementNonce(smartAccount);
        // - get all the signerIds
        // - for every signerId get all the actionIds
        // call onInstall for all sub-modules enabled for a given smartAccount:
        // - signerValidators for every signerId
        // - userOp and erc127Policies for every SignerId
        // - actionPolicies for a given signerId + actionId
        // clean enabledSignerIds(msg.sender)
        // DO NOT NEED to clean enabledActionPolicies as old signerIds are not reachable after nonce increment
        // DO NOT NEED to clean userOpPolicies, actionPolicies, erc1271Policies as old signerIds are not reachable after nonce increment
    }

    function renounceSignerId(bytes32 _signerId) external {
        address smartAccount = msg.sender;
        SignerId signerId = SignerId.wrap(_signerId.mixinNonce(getNonce(msg.sender)));
        // call onInstall for all sub-modules enabled for a given smartAccount and signerId:
        // - signerValidator for a given signerId
        // - userOp and erc127Policies for given SignerId
        // - actionPolicies for a given signerId and all actionIds
        // remove signerId from enabledSignerIds(smartAccount)
        // clean userOpPolicies and erc1271Policies for a given signerId+smartAccount
        // clean actionPolicies for a given signerId+smartAccount and all actionIds
    }

    function renounceUserOpPolicy(bytes32 _signerId, address policy) external {
        SignerId signerId = SignerId.wrap(_signerId.mixinNonce(getNonce(msg.sender)));
        userOpPolicies[signerId].remove(msg.sender, policy);
        _callSubModuleAndHandleReturnData(
                            policy, 
                            abi.encodePacked(
                                abi.encodeWithSelector(
                                    IERC7579Module.onUninstall.selector, 
                                    SignerId.unwrap(signerId)
                                ),
                                address(this), //append self address
                                msg.sender   //append smart account address as original msg.sender
                            )
                        );
    }


    function renounceActionPolicy(bytes32 _signerId, ActionId actionId, address policy) external {
        SignerId signerId = SignerId.wrap(_signerId.mixinNonce(getNonce(msg.sender)));
        actionPolicies[signerId][actionId].remove(msg.sender, policy);

        bytes32 id = keccak256(abi.encodePacked(SignerId.unwrap(signerId), ActionId.unwrap(actionId)));
        _callSubModuleAndHandleReturnData(
                            policy, 
                            abi.encodePacked(
                                abi.encodeWithSelector(
                                    IERC7579Module.onUninstall.selector, 
                                    id
                                ),
                                address(this), //append self address
                                msg.sender   //append smart account address as original msg.sender
                            )
                        );
    }

    function renounce1271Policy(bytes32 _signerId, address policy) external {
        SignerId signerId = SignerId.wrap(_signerId.mixinNonce(getNonce(msg.sender)));
        erc1271Policies[signerId].remove(msg.sender, policy);

        bytes32 id = keccak256(abi.encodePacked("ERC1271 Policy", SignerId.unwrap(signerId)));
        _callSubModuleAndHandleReturnData(
                            policy, 
                            abi.encodePacked(
                                abi.encodeWithSelector(
                                    IERC7579Module.onUninstall.selector, 
                                    id
                                ),
                                address(this), //append self address
                                msg.sender   //append smart account address as original msg.sender
                            )
                        );
    }

    /** 
     * @dev Allows to renounce the permission that has not even been enabled on-chain.
     * It does it by marking the permission enable object that have been signed as renounced
     *
    */
    function renouncePermissionEnableObject(uint64 chainId, bytes32 permissionDigest) public {
        bytes32 permissionEnableObject = keccak256(abi.encodePacked(chainId, permissionDigest));
        _setRenounceStatus(permissionEnableObject, msg.sender, true);
    }



    /*//////////////////////////////////////////////////////////////////////////
                                     PUBLIC INTERFACE
    //////////////////////////////////////////////////////////////////////////*/

    // signerId can be enabled counterfactually, when enable data has been signed
    // but not submitted to the chain yet
    function isSignerIdEnabledOnchain(bytes32 _signerId, address smartAccount) external view returns (bool) {
        SignerId signerId = SignerId.wrap(_signerId.mixinNonce(getNonce(smartAccount)));
        return _isSignerIdEnabled(signerId, smartAccount);
    }

    function _isSignerIdEnabled(SignerId signerId, address smartAccount) internal view returns (bool) {
        return getSignerValidator(signerId, smartAccount) != address(0);
    }


    function changeSignerValidator(SignerId signerId, address newSignerValidator) external {
        _setSignerValidator(signerId, msg.sender, newSignerValidator);
    }

    /*//////////////////////////////////////////////////////////////////////////
                    UserOpBuilder helper
    //////////////////////////////////////////////////////////////////////////*/

    // Checks if the permission has been or hasn't been enabled
    // Reverts if permission has not been enabled properly or altered an thus can not be enabled
    function isPermissionEnabled(bytes calldata data, address smartAccount) public view returns (bool, bytes32) {
        bytes calldata permissionData = _validatePermission(smartAccount, data);
        if (permissionData.length < 36) {
            revert ("permission data too short");
        }

        SignerId signerId = SignerId.wrap(
            bytes32(permissionData[0:32]).mixinNonce(getNonce(msg.sender))
        );

        PermissionDescriptor permissionDescriptor = PermissionDescriptor.wrap(bytes4(permissionData[32:36]));
        uint256 offset = 36;

        // If such a signerId was not enabled, then the whole permission was definitely not enabled
        if(!_isSignerIdEnabled(signerId, smartAccount)) {
            return (false, bytes32(permissionData[0:32]));
        }
        offset += _checkEnabledSignerId(smartAccount, signerId, permissionDescriptor, permissionData[offset:]);

        // If it is not enable mode (we just want to add some policies)
        // or it was enable mode and signerId was properly enabled, 
        // we continue to checking policies
        uint256 totalPolicies; 
        uint256 enabledPolicies;

        totalPolicies += permissionDescriptor.getUserOpPoliciesNumber();
        (offset, enabledPolicies) = _checkEnabledPolicies(
            userOpPolicies[signerId], permissionDescriptor.getUserOpPoliciesNumber(), offset, enabledPolicies, smartAccount, permissionData
        );

        totalPolicies += permissionDescriptor.getActionPoliciesNumber();
        ActionId actionId = ActionId.wrap(bytes32(permissionData[offset:offset+32]));
        offset += 32;
        (offset, enabledPolicies) = _checkEnabledPolicies(
            actionPolicies[signerId][actionId], permissionDescriptor.getActionPoliciesNumber(), offset, enabledPolicies, smartAccount, permissionData
        );

        totalPolicies += permissionDescriptor.get1271PoliciesNumber();
        (offset, enabledPolicies) = _checkEnabledPolicies(
            erc1271Policies[signerId], permissionDescriptor.get1271PoliciesNumber(), offset, enabledPolicies, smartAccount, permissionData
        );

        //now have to return true or false based on checks
        // if exactly all policies are enabled => return true (means permission has been properly enabled)
        // if no policies are enabled => return false (means the permission has not been enabled, and can be enabled)
        // if only part of the policies are enabled => revert (means the permission has not been 
        // properly enabled (or enabled and altered) and CAN NOT be enabled as same policy can not 
        // be enabled twice for same signerId)
        if(enabledPolicies == 0) {
            return (false, bytes32(permissionData[0:32]));
        } else if(enabledPolicies == totalPolicies) {
            return (true, bytes32(permissionData[0:32]));
        } else {
            revert("Permission can not be enabled");
        }
    }

    function _checkEnabledSignerId(
        address smartAccount, 
        SignerId signerId,
        PermissionDescriptor permissionDescriptor, 
        bytes calldata data
    ) internal view returns (uint256 addOffset) {
        address signerValidator;
        // enable signer if required
        if(permissionDescriptor.isSignerEnableMode()) {
            // it was originally signer enable mode
            (addOffset, signerValidator, ) = _parseSigner(data);
            if (signerValidator != getSignerValidator(signerId, smartAccount)) {
                // signerId is enabled, but with the different signerValidator
                revert("Signer Validator altered");
            }
            //otherwise the signer has been properly enabled (with an expected signerValidator).
        } 
    }

    function _checkEnabledPolicies(
        AddressArrayMap4337 storage policies, 
        uint256 numberOfPolicies,
        uint256 offset, 
        uint256 enabledPolicies,
        address smartAccount, 
        bytes calldata permissionData
    ) internal view returns(uint256, uint256) {
        for (uint256 i; i<numberOfPolicies; i++) {
            (address userOpPolicy, bytes calldata policyData) = _parsePolicy(permissionData[offset:]);
            offset += 24+policyData.length;
            if(policies.contains(smartAccount, userOpPolicy)) {
                enabledPolicies++;
            }
        }
        return(offset, enabledPolicies);
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

    /*//////////////////////////////////////////////////////////////////////////
                                    MAPPINGS ACCESS
    //////////////////////////////////////////////////////////////////////////*/

    function getSignerValidator(SignerId signerId, address smartAccount) public view returns (address signerValidator) {
        assembly {
            mstore(0x04, _SIGNER_VALIDATORS_SLOT_SEED)
            mstore(0x00, signerId)
            mstore(0x20, keccak256(0x00, 0x24))  //store hash
            mstore(0x00, smartAccount)
            signerValidator := sload(keccak256(0x00, 0x40))
        }
    }

    function _setSignerValidator(SignerId signerId, address smartAccount, address signerValidator) internal {
        assembly {
            mstore(0x04, _SIGNER_VALIDATORS_SLOT_SEED)
            mstore(0x00, signerId)
            mstore(0x20, keccak256(0x00, 0x24))  //store hash of outer key + slot seed
            mstore(0x00, smartAccount)
            sstore(keccak256(0x00, 0x40), signerValidator)
        }
    }

    function isPermissionObjectRenounced(bytes32 permissionObj, address smartAccount) public view returns (bool res) {
        assembly {
            mstore(0x04, _RENOUNCED_PERMISSIONS_SLOT_SEED)
            mstore(0x00, permissionObj)
            mstore(0x20, keccak256(0x00, 0x24))  //store hash
            mstore(0x00, smartAccount)
            res := sload(keccak256(0x00, 0x40))
        }
    }

    function _setRenounceStatus(bytes32 permissionObj, address smartAccount, bool status) internal {
        assembly {
            mstore(0x04, _RENOUNCED_PERMISSIONS_SLOT_SEED)
            mstore(0x00, permissionObj)
            mstore(0x20, keccak256(0x00, 0x24))  //store hash of outer key + slot seed
            mstore(0x00, smartAccount)
            sstore(keccak256(0x00, 0x40), status)
        }
    }

    function getNonce(address smartAccount) public view returns (uint256 nonce) {
        assembly {
            mstore(0x04, _NONCES_SLOT_SEED)
            mstore(0x00, smartAccount)
            nonce := sload(keccak256(0x00, 0x40))
        }
    }

    function incrementNonce(address smartAccount) internal {
        assembly {
            mstore(0x04, _NONCES_SLOT_SEED)
            mstore(0x00, smartAccount)
            let slot := keccak256(0x00, 0x40)
            sstore(slot, add(sload(slot), 1))
        }
    }

}
