// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { ERC7579ValidatorBase } from "modulekit/Modules.sol";
import { PackedUserOperation } from "modulekit/external/ERC4337.sol";
import { IPermissionValidator } from "contracts/interfaces/validators/IPermissionValidator.sol";
import { IERC7579Account } from  "erc7579/interfaces/IERC7579Account.sol";
import { IAccountExecute} from "modulekit/external/ERC4337.sol";

contract PermissionValidator is ERC7579ValidatorBase, IPermissionValidator {
    /*//////////////////////////////////////////////////////////////////////////
                            CONSTANTS & STORAGE
    //////////////////////////////////////////////////////////////////////////*/

    // bytes32(uint256(keccak256('erc7579.module.permissionvalidator')) - 1)
    bytes32 constant PERMISSION_VALIDATOR_STORAGE_SLOT = 0x73a9885e8be4b58095971868aa2af983b5913f3e08c5b78a3ca0cb6b827458f8;

    type SignerId is bytes32;

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
        //
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
        view
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

        if(_isEnableMode(userOp.signature)) {
           (bytes32 signerId, bytes memory cleanSig) = _validateAndEnablePermissions(userOp);
        } else {
            bytes32 signerId = bytes32(userOp.signature[1:33]);
            // parse cleanSig from userOp.signature
        }

        ISignerValidator(signerValidator).checkSignature(signerId, userOpHash, sig);
        // if 0xffffff => return SIG_VALIDATION_FAILED

        //flows based on selector
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
    function onInstall(bytes calldata data) external override { }

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
    function isInitialized(address smartAccount) external view returns (bool) { }

    /*//////////////////////////////////////////////////////////////////////////
                                     INTERNAL
    //////////////////////////////////////////////////////////////////////////*/

    function _validate7579ExecuteCall(
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
        
    }

    function _validateNativeFunctionCall(
        PackedUserOperation calldata userOp, 
        bytes32 userOpHash
    ) internal returns (ValidationData) {
        // we expect this to be single action userOp, not a batched one
        
        // 1. check enable mode flag (means we enable something before validating userOp.calldata)
        // enable mode can be : 
        // - enable signer => 
        //        in this case we know everything about the permissions we need to apply from 
        //        the signer enable object and we can save some SLOADs by not fetching the data
        //        from the storage. Estimate is it worth it having separate procedure for this 
        //        branch in terms of code readability / gas savings tradeoff
        //        as from code readability perspective it might be better to have a unified flow
        //        of just enbaling all first and then independently processing
        //        because in all other 'enable' cases we will have to SLOAD at least some data
        // - enable action permission for signer
        // - enable policy for signer
        // - enable policy for action permission

        // if this is enable mode, we know the signer from it
        // otherwise we get the signer from signature
        // however it is cheap to get it from the signature

        // 2. validate Single Action

        /*
         - validate signer
         - validate general rules
         - validate action permission
        */

        
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
        return typeID == TYPE_VALIDATOR;
    }
}
