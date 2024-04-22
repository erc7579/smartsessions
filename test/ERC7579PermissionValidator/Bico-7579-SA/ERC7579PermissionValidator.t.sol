// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "erc7579/interfaces/IERC7579Account.sol";
import "erc7579/lib/ModeLib.sol";
import "erc7579/lib/ExecutionLib.sol";
import { ERC7579PermissionValidatorTestBaseUtil } from "./ERC7579PV_Base.t.sol";
import { SingleSignerPermission, ValidAfter, ValidUntil } from "src/ERC7579PermissionValidator/IERC7579PermissionValidator.sol";
import { MockTarget } from "src/modulekit/mocks/MockTarget.sol";
import { DemoPermissionContextBuilder, PermissionSigner, PermissionObjData, PermissionObj, DonutPermissionRequest } from "src/test/demoPermissionContextBuilder/permissionContextBuilder.sol";
import { BiconomyUserOpConstructor } from "src/UserOperationConstructors/BiconomyUserOperationConstructor.sol";

import "forge-std/console2.sol";

//CallType constant CALLTYPE_STATIC = CallType.wrap(0xFE);

contract ERC7579PermissionValidatorTest is ERC7579PermissionValidatorTestBaseUtil {

    uint256 internal constant MODULE_TYPE_VALIDATOR = 1;
    MockTarget target;
    DemoPermissionContextBuilder contextBuilder;
    BiconomyUserOpConstructor userOpConstructor;

    function setUp() public override {
        super.setUp();
        enablePermissionValidator();
        target = new MockTarget();
        contextBuilder = new DemoPermissionContextBuilder();
        userOpConstructor = new BiconomyUserOpConstructor(address(entrypoint));
    }

    function test_test() public {
        console2.log(bicoUserSA.accountId());
    }

    function  test_enable7579PermissionValidator() public {
        assertEq(
            bicoUserSA.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(permissionValidator), ""),
            true
        );
    }

    function test_enableAndUsePermission() public {
        // build the permission
        SingleSignerPermission memory permission = SingleSignerPermission({
            validUntil: ValidUntil.wrap(0),
            validAfter: ValidAfter.wrap(0),
            signatureValidationAlgorithm: address(sigValidatorAlgo),
            signer: abi.encodePacked(permittedSigner.addr),
            policy: address(0xa11ce),
            policyData: ""
        });

        uint64[] memory chainIds = new uint64[](1);
        chainIds[0] = uint64(block.chainid);

        SingleSignerPermission[]
            memory permissions = new SingleSignerPermission[](1);
        permissions[0] = permission;

        (
            bytes memory permissionEnableData,
            bytes memory permissionEnableSignature
        ) = makePermissionEnableData(
            chainIds, 
            permissions, 
            address(bicoUserSA),
            address(defaultValidator),
            permittedSigner
        );

        //console2.logBytes(permissionEnableData);

        PackedUserOperation memory enableAndUsePermissionUserOp = getDefaultUserOp(
            address(bicoUserSA),
            address(permissionValidator)
        );

        // Create calldata for the account to execute
        bytes memory setValueOnTarget = abi.encodeCall(MockTarget.set, 777);
        // Encode the call into the calldata for the userOp
        bytes memory userOpCalldata = abi.encodeCall(
            IERC7579Account.execute,
            (
                ModeLib.encodeSimpleSingle(),
                ExecutionLib.encodeSingle(address(target), uint256(0), setValueOnTarget)
            )
        );
        enableAndUsePermissionUserOp.callData = userOpCalldata;

        bytes32 userOpHash = entrypoint.getUserOpHash(enableAndUsePermissionUserOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(permittedSigner.key, userOpHash);
        bytes memory rawSignature = abi.encodePacked(r, s, v);

        uint256 _permissionIndex = 0;

        bytes memory moduleSignature = getPermissionValidatorSignature(
            permission,
            _permissionIndex,
            rawSignature,
            permissionEnableData,
            permissionEnableSignature
        );

        enableAndUsePermissionUserOp.signature = moduleSignature;

        // Create userOps array
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = enableAndUsePermissionUserOp;

        // Send the userOp to the entrypoint
        entrypoint.handleOps(userOps, payable(address(0x69)));
        assertEq(target.value(), 777);
    }

    function test_PermissionValidatorBuilder() public {
        /*
            1. getPermissionContext 
            2. get all the details for the userOp
            3. try to send the userOp
        */

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
                signer1.key, 
                keccak256("0x123") //should have been the enable permission data digest
            );
        bytes memory dummyEnableSig = abi.encodePacked(r, s, v);

        PermissionObj[] memory permissionObjects = new PermissionObj[](1);
        permissionObjects[0] = 
                PermissionObj({
                    permType: "purchase_donuts",
                    permObjData: PermissionObjData({
                        bakeryAddress: address(0x123),
                        donutsLimit: uint256(100)
                    }),
                    required: true
                });

        // get the permission context
        bytes memory permissionContext = contextBuilder.getPermissionContext(
            DonutPermissionRequest({
                signer: PermissionSigner({
                    signerType: "ECDSA",
                    pubKey: permittedSigner.addr
                }),
                permissionObjs: permissionObjects
            }),
            address(permissionValidator),
            address(sigValidatorAlgo),
            dummyEnableSig
        );

        uint256 nonce = userOpConstructor.getNonceWithContext(
            address(bicoUserSA), 
            permissionContext
        );

        Execution[] memory executionsArray = new Execution[](1);
        executionsArray[0] = Execution({
            target: address(target),
            value: 0,
            callData: abi.encodeWithSignature("set(uint256)", 777)
        });

        bytes memory callData = userOpConstructor.getCallDataWithContext(
            address(bicoUserSA),
            executionsArray,
            permissionContext
        );

        PackedUserOperation memory userOp = getDefaultUserOp(
            address(bicoUserSA),
            address(permissionValidator)
        );

        userOp.callData = callData;
        userOp.nonce = nonce;

        bytes32 userOpHash = entrypoint.getUserOpHash(userOp);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(permittedSigner.key, userOpHash);
        bytes memory rawSignature = abi.encodePacked(r1, s1, v1);
        userOp.signature = rawSignature;

        bytes memory moduleSignature = userOpConstructor.getSignatureWithContext(
            address(bicoUserSA),
            userOp,
            permissionContext
        );

        userOp.signature = moduleSignature;

        // Create userOps array
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        // Send the userOp to the entrypoint
        entrypoint.handleOps(userOps, payable(address(0x69)));
        assertEq(target.value(), 777);

    }


    function enablePermissionValidator() public {
        PackedUserOperation memory userOp = getDefaultUserOp(
            address(bicoUserSA), 
            address(defaultValidator)
        );

        bytes memory userOpCalldata = abi.encodeCall(
            IERC7579Account.installModule,
            (
                MODULE_TYPE_VALIDATOR,
                address(permissionValidator),
                ""
            )
        );

        userOp.callData = userOpCalldata;
        bytes32 userOpHash = entrypoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signer1.key, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        userOp.signature = signature;

        // Create userOps array
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        // Send the userOp to the entrypoint
        entrypoint.handleOps(userOps, payable(address(0x69)));
    }

    function makePermissionEnableData(
        uint64[] memory chainIds,
        SingleSignerPermission[] memory permissions,
        address smartAccount,
        address enableSignatureValidatorModule,
        Account memory enableSigDataSigner
    ) internal view returns (bytes memory, bytes memory) {
        
        bytes32[] memory permissionIds = new bytes32[](permissions.length);
        for (uint256 i = 0; i < permissions.length; i++) {
            permissionIds[i] = permissionValidator.getPermissionId(
                permissions[i]
            );
        }

        /*
        permissionEnableData:
            encodePacked:
                permissions.length (uint8)
                chainIds[] (uint64[])
                permissionIds[] (bytes32[])
        
        permissionsEnableSignature: signature on the keccak256(permissionEnableData)

        */


        bytes memory permissionEnableData = abi.encodePacked(
            uint8(permissions.length)
        );
        for (uint256 i = 0; i < chainIds.length; ++i) {
            permissionEnableData = abi.encodePacked(
                permissionEnableData,
                chainIds[i]
            );
        }
        permissionEnableData = abi.encodePacked(permissionEnableData, permissionIds);

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n52",
                keccak256(permissionEnableData),
                smartAccount
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(enableSigDataSigner.key, digest);
        /*
        bytes memory erc1271Signature = abi.encode(
            abi.encodePacked(r, s, v),
            enableSignatureValidatorModule
        );
        */
         bytes memory erc1271Signature = abi.encodePacked(r, s, v);
        return (permissionEnableData, erc1271Signature);
    }

    function getPermissionValidatorSignature(
        SingleSignerPermission memory permission,
        uint256 _permissionIndex, 
        bytes memory rawSignature,
        bytes memory permissionEnableData,
        bytes memory permissionEnableSignature
    ) internal view returns (bytes memory) {
        return 
        abi.encodePacked(
            uint8(0x01),
            abi.encode(
                _permissionIndex,
                permission,
                permissionEnableData,
                permissionEnableSignature,
                rawSignature
            )
        );
    }
}


