// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Test } from "forge-std/Test.sol";
import { Solarray } from "solarray/Solarray.sol";
import {
    RhinestoneModuleKit,
    ModuleKitHelpers,
    ModuleKitUserOp,
    AccountInstance,
    UserOpData
} from "modulekit/ModuleKit.sol";
import { MODULE_TYPE_VALIDATOR, MODULE_TYPE_EXECUTOR, Execution } from "modulekit/external/ERC7579.sol";
import { SmartSession } from "contracts/SmartSession.sol";
import { EncodeLib } from "contracts/lib/EncodeLib.sol";
import { ISigner } from "contracts/interfaces/ISigner.sol";
import "contracts/DataTypes.sol";
import { EncodeLib } from "contracts/lib/EncodeLib.sol";
import { YesSigner } from "./mock/YesSigner.sol";
import { MockTarget } from "./mock/MockTarget.sol";
import { YesPolicy } from "./mock/YesPolicy.sol";
import { EIP1271_MAGIC_VALUE, IERC1271 } from "module-bases/interfaces/IERC1271.sol";

import "forge-std/console2.sol";

contract SmartSessionBaseTest is RhinestoneModuleKit, Test {
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using EncodeLib for SignerId;

    // account and modules
    AccountInstance internal instance;
    SmartSession internal smartSession;
    YesPolicy internal yesPolicy;
    YesSigner internal yesSigner;

    MockTarget target;
    Account sessionSigner1;
    Account sessionSigner2;

    SignerId defaultSigner1;
    SignerId defaultSigner2;

    function setUp() public virtual {
        instance = makeAccountInstance("smartaccount");

        sessionSigner1 = makeAccount("sessionSigner1");
        sessionSigner2 = makeAccount("sessionSigner2");

        defaultSigner1 = SignerId.wrap(bytes32(hex"01"));
        defaultSigner2 = SignerId.wrap(bytes32(hex"02"));

        smartSession = new SmartSession();
        target = new MockTarget();
        yesSigner = new YesSigner();
        yesPolicy = new YesPolicy();

        InstallSessions[] memory installData = new InstallSessions[](0);

        instance.installModule({
            moduleTypeId: MODULE_TYPE_VALIDATOR,
            module: address(smartSession),
            data: abi.encode(installData)
        });

        vm.startPrank(instance.account);
        smartSession.setSigner(defaultSigner1, ISigner(address(yesSigner)), "");

        PolicyData[] memory policyData = new PolicyData[](1);
        policyData[0] = PolicyData({ policy: address(yesPolicy), initData: "" });
        smartSession.enableUserOpPolicies(defaultSigner1, policyData);
        vm.stopPrank();
    }

    function test_exec() public {
        UserOpData memory userOpData = instance.getExecOps({
            target: address(target),
            value: 0,
            callData: abi.encodeCall(MockTarget.setValue, (1337)),
            txValidator: address(smartSession)
        });

        userOpData.userOp.signature = EncodeLib.encodeUse({ signerId: defaultSigner1, sig: hex"4141414141" });
        userOpData.execUserOps();
    }

    function test_enable_exec() public {
        UserOpData memory userOpData = instance.getExecOps({
            target: address(target),
            value: 0,
            callData: abi.encodeCall(MockTarget.setValue, (1337)),
            txValidator: address(smartSession)
        });

        PolicyData[] memory policyData = new PolicyData[](1);
        policyData[0] = PolicyData({ policy: address(yesPolicy), initData: "" });

        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({ actionId: ActionId.wrap(bytes32(hex"01")), actionPolicies: policyData });

        EnableSessions memory enableData = EnableSessions({
            isigner: ISigner(address(yesSigner)),
            isignerInitData: "",
            userOpPolicies: policyData,
            erc1271Policies: new PolicyData[](0),
            actions: actions,
            permissionEnableSig: ""
        });

        bytes32 hash = smartSession.getDigest(defaultSigner2, instance.account, enableData);
        enableData.permissionEnableSig = abi.encodePacked(instance.defaultValidator, sign(hash, 1));

        userOpData.userOp.signature = EncodeLib.encodeEnable(defaultSigner2, hex"4141414142", enableData);
        console2.log("enable within session");
        userOpData.execUserOps();
    }

    function sign(bytes32 hash, uint256 privKey) internal pure returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, hash);

        // Set the signature
        signature = abi.encodePacked(r, s, v);
    }
}
