// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { ERC7579ValidatorBase, ERC7579ExecutorBase } from "modulekit/Modules.sol";
import { PackedUserOperation } from "modulekit/external/ERC4337.sol";
import { AddressArray, AddressArrayLib } from "contracts/utils/AddressArrayLib.sol";
import { IPermissionManager } from "contracts/interfaces/validators/IPermissionManager.sol";
import { IERC7579Account } from  "erc7579/interfaces/IERC7579Account.sol";
import { IModule as IERC7579Module } from "erc7579/interfaces/IERC7579Module.sol";
import { IAccountExecute} from "modulekit/external/ERC4337.sol";
import { ISignerValidator } from "contracts/interfaces/ISignerValidator.sol";
import { ITrustedForwarder } from "contracts/utils/ITrustedForwarder.sol";
import { IUserOpPolicy, IActionPolicy } from "contracts/interfaces/IPolicies.sol";
import { IERC165 } from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import "forge-std/console2.sol";


contract PermissionManager is ERC7579ValidatorBase, ERC7579ExecutorBase, IPermissionManager {
    /*//////////////////////////////////////////////////////////////////////////
                            CONSTANTS & STORAGE
    //////////////////////////////////////////////////////////////////////////*/

    // bytes32(uint256(keccak256('erc7579.module.permissionvalidator')) - 1)
    bytes32 constant PERMISSION_VALIDATOR_STORAGE_SLOT = 0x73a9885e8be4b58095971868aa2af983b5913f3e08c5b78a3ca0cb6b827458f8;

    using AddressArrayLib for AddressArray;

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
        
        // change bytes to struct similar to what @zeroknots did, but also add library to parse it to get list of addresses
        // struct of 5 items bytes32 each will give us 160bytes = 8 addresses
        mapping(SignerId => mapping (address smartAccount => AddressArray)) userOpPolicies;  
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
     * @return sigValidationResult the result of the signature validation, which can be:
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
        returns (ValidationData)
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
        bytes memory cleanSig;
        address signerValidator;

        // if this is enable mode, we know the signer from it
        // otherwise we get the signer from signature
        // however it is cheap to get it from the signature
        if(_isEnableMode(userOp.signature)) {
          // (SignerId signerId, bytes memory cleanSig) = _validateAndEnablePermissions(userOp);
          // signer validator can also be obtained from enable data in many cases, saving one SLOAD
        } else {
            signerId = SignerId.wrap(bytes32(userOp.signature[1:33]));
            cleanSig = userOp.signature[33:];
            signerValidator = _permissionValidatorStorage().signers[signerId][msg.sender];
        }

        if (ISignerValidator(signerValidator).checkSignature(SignerId.unwrap(signerId), msg.sender, userOpHash, cleanSig) == EIP1271_FAILED) {
            return VALIDATION_FAILED;
        }
        console2.log("Signature validation at ISignerValidator.checkSignature passed");

        // Check userOp level Policies
        AddressArray storage policies = _permissionValidatorStorage().userOpPolicies[signerId][msg.sender];
        for(uint256 i; i < policies.length(); i++) {
            // temporary; 
            // in fact we need to intersect validation datas from all policies and pass next to then intersect with
            // validation data from the action policies
            //console2.log("Policy address: ", policies.get(i));
            uint256 vd = IUserOpPolicy(policies.get(i)).checkUserOp(SignerId.unwrap(signerId), userOp); 
        }

        console2.log("UserOp Policied verification passed");

        //flows based on selector
        // CHANGE to receiving and intersecting validation data from policies
        if (selector == IERC7579Account.execute.selector) {
            return _validate7579ExecuteCall(signerId, userOp, userOpHash);
        } else {
            return _validateNativeFunctionCall(signerId, userOp, userOpHash);
        }
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
        return EIP1271_FAILED;
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
        }
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

    /*//////////////////////////////////////////////////////////////////////////
                                     INTERNAL
    //////////////////////////////////////////////////////////////////////////*/

    function _validate7579ExecuteCall(
        SignerId signerId,
        PackedUserOperation calldata userOp, 
        bytes32 userOpHash
    ) internal returns (ValidationData) {

        // check execution modes and handle stuff accordingly

        // if the execution mode is not known (some custom one),
        // then the solutions are:
        // a) revert
        // b) fallback to some handler 
        //    will have to think how to properly install/uninstall it on the account
        //    ideally via 7484 integration
        return VALIDATION_SUCCESS;
        
    }

    function _validateNativeFunctionCall(
        SignerId signerId,
        PackedUserOperation calldata userOp, 
        bytes32 userOpHash
    ) internal returns (ValidationData) {
        // we expect this to be single action userOp, not a batched one
        // Validate Single Action

        // - validate general rules
        // - validate action permission
        return VALIDATION_SUCCESS;
    }

    function _enableSigner(
        SignerId signerId, 
        address signerValidator, 
        address smartAccount, 
        bytes calldata signerData
    ) internal {   
        bytes memory _data = abi.encodePacked(signerId, signerData);

        // set signerValidator for signerId and smartAccount
        _permissionValidatorStorage().signers[signerId][smartAccount] = signerValidator;

        _initSubmodule(signerValidator, signerId, smartAccount, _data);
    }

    function _enableUserOpPolicy(
        SignerId signerId, 
        address userOpPolicy, 
        address smartAccount, 
        bytes calldata policyData
    ) internal {
        bytes memory _data = abi.encodePacked(signerId, policyData);

        // set userOpPolicy for signerId and smartAccount
        _addUserOpPolicy(signerId, smartAccount, userOpPolicy);

        _initSubmodule(userOpPolicy, signerId, smartAccount, _data);
    }

    function _addUserOpPolicy(SignerId signerId, address smartAccount, address userOpPolicy) internal {
        AddressArray storage policies = _permissionValidatorStorage().userOpPolicies[signerId][smartAccount];
        if(!policies.contains(userOpPolicy)) {
            policies.push(userOpPolicy);
            //console2.log("check from storage: ", _permissionValidatorStorage().userOpPolicies[signerId][smartAccount].data[policies.lastUsedIndex()]);
        } else {
            // same policy can not be used twice for the same signerId and smartAccount, as
            // inside the policy contract the config is stored as signerId=>smartAccount=>config

            revert UserOpPolicyAlreadyUsed(signerId, smartAccount, userOpPolicy);
        }
    }

    function _initSubmodule( 
        address subModule, 
        SignerId signerId,
        address smartAccount, 
        bytes memory subModuleInitData
    ) internal {
        try IERC165(subModule).supportsInterface(type(ITrustedForwarder).interfaceId) returns (bool supported) {
            if(supported) {
                // set trusted forwarder via SA
                // This module SHOULD be installed as an executor on the smart account
                // to be able to call executeFromExecutor
                // The check allows to avoid excess sstore's in case sub-module uses id-less approach
                if(!ITrustedForwarder(subModule).isTrustedForwarder(address(this), smartAccount, SignerId.unwrap(signerId))) {
                    _execute(
                        smartAccount, 
                        subModule,
                        0, 
                        abi.encodeWithSelector(ITrustedForwarder.setTrustedForwarder.selector, address(this), signerId)
                    );
                }
                
                // setup signerValidator for given signerId and smartAccount
                (bool success, ) = subModule.call(
                    abi.encodePacked(
                        abi.encodeCall(IERC7579Module.onInstall, (subModuleInitData)),
                        address(this),
                        smartAccount
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
        //return signature[0] == 0x01;
        return false;
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
