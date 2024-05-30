// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Test } from "forge-std/Test.sol";
import {
    RhinestoneModuleKit,
    ModuleKitHelpers,
    ModuleKitUserOp,
    AccountInstance,
    UserOpData
} from "modulekit/ModuleKit.sol";
import { MODULE_TYPE_VALIDATOR, MODULE_TYPE_EXECUTOR } from "modulekit/external/ERC7579.sol";
import { PermissionManager } from "contracts/validators/PermissionManager.sol";
import { SimpleSigner } from "contracts/test/mocks/SimpleSigner.sol";

import "forge-std/console2.sol";

contract PermissionManagerBaseTest is RhinestoneModuleKit, Test {
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;

    // account and modules
    AccountInstance internal instance;
    PermissionManager internal permissionManager;
    SimpleSigner internal simpleSignerValidator;
    address sessionSigner1;
    uint256 sessionSigner1Pk;

    bytes32 signerId;

    function setUp() public {
        init();

        // Create the validator
        permissionManager = new PermissionManager();
        vm.label(address(permissionManager), "PermissionManager");

        // Create the signer
        simpleSignerValidator = new SimpleSigner();
        vm.label(address(simpleSignerValidator), "SimpleSignerValidator");

        // Create the account and install as a validator and as an executor
        instance = makeAccountInstance("PermissionManager");
        vm.deal(address(instance.account), 10 ether);

        (sessionSigner1, sessionSigner1Pk) = makeAddrAndKey("sessionSigner1");

        //example signerId
        signerId = keccak256(abi.encodePacked("Signer Id for ", instance.account, simpleSignerValidator, block.timestamp));

        instance.installModule({
            moduleTypeId: MODULE_TYPE_EXECUTOR,
            module: address(permissionManager),
            data: abi.encodePacked(bytes1(uint8(MODULE_TYPE_EXECUTOR)))
        });

        instance.installModule({
            moduleTypeId: MODULE_TYPE_VALIDATOR,
            module: address(permissionManager),
            data: abi.encodePacked(bytes1(uint8(MODULE_TYPE_VALIDATOR)), signerId, simpleSignerValidator, sessionSigner1)
        });
        
        /*

        */
    }

    function testExec() public {
        // Create a target address and send some ether to it
        address target = makeAddr("target");
        uint256 value = 1 ether;

        // Get the current balance of the target
        uint256 prevBalance = target.balance;

        // Get the UserOp data (UserOperation and UserOperationHash)
        UserOpData memory userOpData = instance.getExecOps({
            target: target,
            value: value,
            callData: "",
            txValidator: address(permissionManager)
        });

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionSigner1Pk, userOpData.userOpHash);

        // Set the signature
        bytes memory signature = abi.encodePacked(
            bytes1(0x00), //not enable mode
            signerId,
            r,s,v
        );
        userOpData.userOp.signature = signature;
        
        // Execute the UserOp
        userOpData.execUserOps();

        // Check if the balance of the target has NOT increased
        assertEq(target.balance, prevBalance+value, "Balance not increased");
    }
}
