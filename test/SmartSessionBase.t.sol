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
import { IRegistry } from "contracts/interfaces/IRegistry.sol";
import "contracts/DataTypes.sol";
import { EncodeLib } from "contracts/lib/EncodeLib.sol";
import { YesSigner } from "./mock/YesSigner.sol";
import { MockRegistry } from "./mock/MockRegistry.sol";
import { MockTarget } from "./mock/MockTarget.sol";
import { YesPolicy } from "./mock/YesPolicy.sol";
import { EIP1271_MAGIC_VALUE, IERC1271 } from "module-bases/interfaces/IERC1271.sol";

import "forge-std/console2.sol";

contract SmartSessionTestHelpers is Test {

    IRegistry constant registry = IRegistry(0x000000000069E2a187AEFFb852bF3cCdC95151B2);
    SmartSession constant smartSession = SmartSession(0x006F777185cf3F0B152E8CEE93587395Aee15129);

    function sign(bytes32 hash, uint256 privKey) internal pure returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, hash);

        // Set the signature
        signature = abi.encodePacked(r, s, v);
    }

    function makeMultiChainEnableData(Session memory session, AccountInstance memory instance, SmartSessionMode mode) internal view returns (EnableSessions memory enableData) {
    
        enableData = EnableSessions({
            sessionIndex: 1,
            hashesAndChainIds: "",
            sessionToEnable: session,
            permissionEnableSig: ""
        });

        bytes32 sessionDigest = smartSession.getDigest({
            isigner: session.isigner, 
            account: instance.account, 
            data: session, 
            mode: mode
        });

        enableData.hashesAndChainIds = abi.encodePacked(
            uint64(181818), //random chainId
            sessionDigest,
            uint64(block.chainid),
            sessionDigest
        );
    }
}

contract SmartSessionTestBase is SmartSessionTestHelpers, RhinestoneModuleKit {
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using EncodeLib for SignerId;

    // account and modules
    AccountInstance internal instance;
    //SmartSession internal smartSession;
    YesPolicy internal yesPolicy;
    YesSigner internal yesSigner;

    MockTarget target;
    Account sessionSigner1;
    Account sessionSigner2;

    SignerId defaultSignerId1;
    SignerId defaultSignerId2;

    function setUp() public virtual {
        instance = makeAccountInstance("smartaccount");

        sessionSigner1 = makeAccount("sessionSigner1");
        sessionSigner2 = makeAccount("sessionSigner2");

        IRegistry _registry = IRegistry(address(new MockRegistry()));
        vm.etch(address(registry), address(_registry).code);

        SmartSession _smartSession = new SmartSession();
        vm.etch(address(smartSession), address(_smartSession).code);

        target = new MockTarget();
        yesSigner = new YesSigner();
        yesPolicy = new YesPolicy();

        Session[] memory installData = new Session[](0);

        instance.installModule({
            moduleTypeId: MODULE_TYPE_VALIDATOR,
            module: address(smartSession),
            data: abi.encode(installData)
        });
    }
}

contract SmartSessionBasicTest is SmartSessionTestBase {

    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using EncodeLib for SignerId;

    function setUp() public virtual override {
        super.setUp();

        vm.startPrank(instance.account);
        PolicyData[] memory policyData = new PolicyData[](1);
        policyData[0] = PolicyData({ policy: address(yesPolicy), initData: "" });
        Session[] memory sessions = new Session[](1);
        sessions[0] = Session({
            isigner: ISigner(address(yesSigner)),
            salt: bytes32(0),
            isignerInitData: "defaultSigner1",
            userOpPolicies: policyData,
            erc1271Policies: new PolicyData[](0),
            actions: new ActionData[](0)
        });

        SignerId[] memory signerIds = smartSession.enableSessions(sessions);
        defaultSignerId1 = signerIds[0];
        vm.stopPrank();
    }

    function test_exec() public {
        UserOpData memory userOpData = instance.getExecOps({
            target: address(target),
            value: 0,
            callData: abi.encodeCall(MockTarget.setValue, (1337)),
            txValidator: address(smartSession)
        });

        userOpData.userOp.signature = EncodeLib.encodeUse({ signerId: defaultSignerId1, sig: hex"4141414141" });
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

        Session memory session = Session({
            isigner: ISigner(address(yesSigner)),
            salt: bytes32(0),
            isignerInitData: "defaultSigner2",
            userOpPolicies: policyData,
            erc1271Policies: new PolicyData[](0),
            actions: actions
        });

        EnableSessions memory enableData = makeMultiChainEnableData(session, instance, SmartSessionMode.UNSAFE_ENABLE);

        bytes32 hash = keccak256(enableData.hashesAndChainIds);
        enableData.permissionEnableSig = abi.encodePacked(instance.defaultValidator, sign(hash, 1));
        
        SignerId signerId = smartSession.getSignerId(session);
        userOpData.userOp.signature = EncodeLib.encodeEnable(signerId, hex"4141414142", enableData);
        userOpData.execUserOps();
    }
}

