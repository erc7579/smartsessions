// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import { SmartAccount } from "bico-sa/SmartAccount.sol";
import { R1Validator } from "bico-sa/modules/validators/R1Validator.sol";
import { AccountFactory } from "bico-sa/factory/AccountFactory.sol";
import { ERC7579PermissionValidator } from "src/ERC7579PermissionValidator/ERC7579PermissionValidator.sol";
import { Secp256K1SigValidationAlgorithm } from "src/ERC7579PermissionValidator/SigValidation/Secp256K1.sol";

import "src/modulekit/EntryPoint.sol";

contract ERC7579PermissionValidatorTestBaseUtil is Test {

    SmartAccount bicoImplementation;
    SmartAccount bicoUserSA;
    R1Validator defaultValidator;
    AccountFactory bicoSAFactory;
    ERC7579PermissionValidator permissionValidator;
    Secp256K1SigValidationAlgorithm sigValidatorAlgo;
    

    IEntryPoint entrypoint;

    Account signer1 = makeAccount("signer1");
    Account signer2 = makeAccount("signer2");
    Account permittedSigner = makeAccount("permittedSigner");

    function setUp() public virtual {

        entrypoint = etchEntrypoint();
        bicoImplementation = new SmartAccount();
        defaultValidator = new R1Validator();
        permissionValidator = new ERC7579PermissionValidator();
        bicoSAFactory = new AccountFactory(address(bicoImplementation));
        sigValidatorAlgo = new Secp256K1SigValidationAlgorithm();

        bytes memory initialValidatorSetupData = abi.encodePacked(signer1.addr);

        uint256 deploymentIndex = 0;
        address bicoUserSAExpectedAddress = bicoSAFactory.getCounterFactualAddress(
            address(defaultValidator),
            initialValidatorSetupData,
            deploymentIndex
        );
        vm.deal(address(bicoUserSAExpectedAddress), 1 ether);

        PackedUserOperation memory userOp = getDefaultUserOp(bicoUserSAExpectedAddress, address(defaultValidator));
        userOp.initCode = initCode(address(defaultValidator), initialValidatorSetupData, deploymentIndex);

        bytes32 userOpHash = entrypoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signer1.key, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        userOp.signature = signature;

        // Create userOps array
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        // Send the userOp to the entrypoint
        entrypoint.handleOps(userOps, payable(address(0x69)));

        bicoUserSA = SmartAccount(payable(bicoUserSAExpectedAddress));
    }

    function test_DeploySA() public {
        
    }

    function getDefaultUserOp(address sender, address validator) internal returns (PackedUserOperation memory userOp) {
        userOp = PackedUserOperation({
            sender: sender,
            nonce: getNonce(sender, validator),
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(abi.encodePacked(uint128(2e6), uint128(2e6))),
            preVerificationGas: 2e6,
            gasFees: bytes32(abi.encodePacked(uint128(2e6), uint128(2e6))),
            paymasterAndData: bytes(""),
            signature: abi.encodePacked(hex"41414141")
        });
    }

    function getNonce(address account, address validator) internal returns (uint256 nonce) {
        uint192 key = uint192(bytes24(bytes20(address(validator))));
        nonce = entrypoint.getNonce(address(account), key);
    }

    function initCode(
        address initialValidatorSetupContract,
        bytes memory initialValidatorSetupData,
        uint256 index
    )
        internal
        view
        returns (bytes memory _initCode)
    {
        _initCode = abi.encodePacked(
            address(bicoSAFactory),
            abi.encodeCall(
                bicoSAFactory.createAccount,
                (
                    address(initialValidatorSetupContract), 
                    initialValidatorSetupData, 
                    index
                )
            )
        );
    }
}