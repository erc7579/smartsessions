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
import { MockTarget } from "./mock/MockTarget.sol";
import { YesPolicy } from "./mock/YesPolicy.sol";
import { MockRegistry } from "./mock/MockRegistry.sol";
import { SimpleSigner } from "./mock/SimpleSigner.sol";
import { SimpleGasPolicy } from "./mock/SimpleGasPolicy.sol";
import { TimeFramePolicy } from "./mock/TimeFramePolicy.sol";
import { ValueLimitPolicy } from "./mock/ValueLimitPolicy.sol";
import { EIP1271_MAGIC_VALUE, IERC1271 } from "module-bases/interfaces/IERC1271.sol";
import { MockK1Validator } from "test/mock/MockK1Validator.sol";
import { UserOperationBuilder } from "contracts/erc7679/UserOpBuilder.sol";
import { ModeLib, ModeCode as ExecutionMode } from "erc7579/lib/ModeLib.sol";

import "forge-std/console2.sol";

IRegistry constant registry = IRegistry(0x0000000000E23E0033C3e93D9D4eBc2FF2AB2AEF);

contract SmartSessionTest is RhinestoneModuleKit, Test {
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using EncodeLib for SignerId;

    // account and modules
    AccountInstance internal instance;
    MockK1Validator internal mockK1;
    SmartSession internal smartSession;
    YesPolicy internal yesPolicy;
    YesSigner internal yesSigner;
    SimpleSigner internal simpleSigner;
    SimpleGasPolicy internal simpleGasPolicy;
    TimeFramePolicy internal timeFramePolicy;
    ValueLimitPolicy internal valueLimitPolicy;

    MockTarget target;
    Account sessionSigner1;
    Account sessionSigner2;
    Account owner;

    SignerId defaultSigner1;
    SignerId defaultSigner2;

    function setUp() public virtual {
        instance = makeAccountInstance("smartaccount");
        mockK1 = new MockK1Validator();

        IRegistry _registry = IRegistry(address(new MockRegistry()));
        vm.etch(address(registry), address(_registry).code);

        owner = makeAccount("owner");
        sessionSigner1 = makeAccount("sessionSigner1");
        sessionSigner2 = makeAccount("sessionSigner2");

        smartSession = new SmartSession();
        target = new MockTarget();
        yesSigner = new YesSigner();
        yesPolicy = new YesPolicy();
        simpleSigner = new SimpleSigner();
        simpleGasPolicy = new SimpleGasPolicy();
        timeFramePolicy = new TimeFramePolicy();
        valueLimitPolicy = new ValueLimitPolicy();

        defaultSigner1 = smartSession.getSignerId(ISigner(address(simpleSigner)), abi.encodePacked(sessionSigner1.addr));
        defaultSigner2 = smartSession.getSignerId(ISigner(address(simpleSigner)), abi.encodePacked(sessionSigner2.addr));

        instance.installModule({
            moduleTypeId: MODULE_TYPE_VALIDATOR,
            module: address(mockK1),
            data: abi.encodePacked(owner.addr)
        });

        InstallSessions[] memory installData = new InstallSessions[](0);
        instance.installModule({
            moduleTypeId: MODULE_TYPE_VALIDATOR,
            module: address(smartSession),
            data: abi.encode(installData)
        });
    }

    function test_use_Permissions_SingleExecution() public {
        uint256 valueToSet = 1337;
        assertFalse(target.getValue() == valueToSet);
        _preEnablePermissions();

        UserOpData memory userOpData = instance.getExecOps({
            target: address(target),
            value: 0,
            callData: abi.encodeCall(MockTarget.setValue, (1337)),
            txValidator: address(smartSession)
        });

        bytes memory sig = sign(userOpData.userOpHash, sessionSigner1.key);
        userOpData.userOp.signature = EncodeLib.encodeUse({ signerId: defaultSigner1, sig: sig });
        userOpData.execUserOps();
        assertEq(target.getValue(), valueToSet);
    }

    function test_use_Permissions_BatchExecution() public {
        uint256 valueToSet = 1337;
        _preEnablePermissions();

        uint256 numberOfExecs = 3;
        Execution[] memory executions = new Execution[](numberOfExecs);
        for (uint256 i = 0; i < numberOfExecs; i++) {
            executions[i] = Execution({
                target: address(target),
                value: 0,
                callData: abi.encodeCall(MockTarget.setValue, (valueToSet + i + 1))
            });
        }
        UserOpData memory userOpData =
            instance.getExecOps({ executions: executions, txValidator: address(smartSession) });

        bytes memory sig = sign(userOpData.userOpHash, sessionSigner1.key);
        userOpData.userOp.signature = EncodeLib.encodeUse({ signerId: defaultSigner1, sig: sig });
        userOpData.execUserOps();
        assertEq(target.getValue(), valueToSet + numberOfExecs);
    }

    function test_enable_And_Use_Permissions_Unsafe_Enable() public {
        uint256 valueToSet = 1337;
        UserOpData memory userOpData = instance.getExecOps({
            target: address(target),
            value: 518 * 1e15,
            callData: abi.encodeCall(MockTarget.setValue, (valueToSet)),
            txValidator: address(smartSession)
        });

        EnableSessions memory enableData = _prepareMockEnableData();

        bytes memory rawSig = sign(userOpData.userOpHash, sessionSigner2.key);
        userOpData.userOp.signature = EncodeLib.encodeEnable(defaultSigner2, rawSig, enableData);
        userOpData.execUserOps();
        assertEq(target.getValue(), valueToSet);
    }

    function test_UserOpBuilderFlow() public {
        uint256 valueToSet = 2517;
        assertFalse(target.getValue() == valueToSet);

        address ep = address(instance.aux.entrypoint);
        UserOperationBuilder userOpBuilder = new UserOperationBuilder(ep);

        UserOpData memory userOpData =
            instance.getExecOps({ target: address(0), value: 0, callData: "", txValidator: address(0) });

        uint192 nonceKey = uint192(uint160(address(smartSession))) << 32;
        EnableSessions memory enableData = _prepareMockEnableData();
        bytes memory context = EncodeLib.encodeContext(
            nonceKey, //192 bits, 24 bytes
            ModeLib.encodeSimpleSingle(), //execution mode, 32 bytes
            defaultSigner2,
            enableData
        );

        uint256 nonce = userOpBuilder.getNonce(instance.account, context);

        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution(address(target), 0, abi.encodeCall(MockTarget.setValue, (valueToSet)));
        bytes memory callData = userOpBuilder.getCallData(instance.account, executions, context);

        userOpData.userOp.nonce = nonce;
        userOpData.userOp.callData = callData;
        userOpData.userOpHash = instance.aux.entrypoint.getUserOpHash(userOpData.userOp);

        //sign userOp
        userOpData.userOp.signature = sign(userOpData.userOpHash, sessionSigner2.key);
        bytes memory formattedSig = userOpBuilder.formatSignature(instance.account, userOpData.userOp, context);
        userOpData.userOp.signature = formattedSig;
        userOpData.execUserOps();
        assertEq(target.getValue(), valueToSet);

        // TRY AGAIN WITH THE PERMISSION ALREADY ENABLED
        uint256 nonce2 = userOpBuilder.getNonce(instance.account, context);

        executions[0] = Execution(address(target), 0, abi.encodeCall(MockTarget.setValue, (valueToSet + 33)));
        callData = userOpBuilder.getCallData(instance.account, executions, context);

        userOpData.userOp.nonce = nonce2;
        userOpData.userOp.callData = callData;
        userOpData.userOpHash = instance.aux.entrypoint.getUserOpHash(userOpData.userOp);

        //sign userOp
        userOpData.userOp.signature = sign(userOpData.userOpHash, sessionSigner2.key);
        formattedSig = userOpBuilder.formatSignature(instance.account, userOpData.userOp, context);
        userOpData.userOp.signature = formattedSig;
        userOpData.execUserOps();
        assertEq(target.getValue(), valueToSet + 33);
    }

    /// =================================================================

    function sign(bytes32 hash, uint256 privKey) internal pure returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, hash);

        // Set the signature
        signature = abi.encodePacked(r, s, v);
    }

    function _preEnablePermissions() internal {
        vm.startPrank(instance.account);
        smartSession.setSigner({
            signerId: defaultSigner1,
            signer: ISigner(address(simpleSigner)),
            initData: abi.encodePacked(sessionSigner1.addr)
        });

        //enable simple gas policy as userOpPolicy
        PolicyData[] memory policyData = new PolicyData[](1);
        bytes memory policyInitData = abi.encodePacked(uint256(2 ** 256 - 1));
        policyData[0] = PolicyData({ policy: address(simpleGasPolicy), initData: policyInitData });
        smartSession.enableUserOpPolicies(defaultSigner1, policyData);

        // enable timeframe policy  as userOpPolicy and actionPolicy
        policyInitData = abi.encodePacked(uint128(block.timestamp + 1000), uint128(block.timestamp - 1));
        policyData[0] = PolicyData({ policy: address(timeFramePolicy), initData: policyInitData });
        smartSession.enableUserOpPolicies(defaultSigner1, policyData);
        ActionId actionId = ActionId.wrap(keccak256(abi.encodePacked(address(target), MockTarget.setValue.selector)));

        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({ actionId: actionId, actionPolicies: policyData });
        smartSession.enableActionPolicies(defaultSigner1, actions);
        vm.stopPrank();
    }

    function _prepareMockEnableData() internal view returns (EnableSessions memory enableData) {
        PolicyData[] memory userOpPolicyData = new PolicyData[](1);
        bytes memory policyInitData = abi.encodePacked(uint256(2 ** 256 - 1));
        userOpPolicyData[0] = PolicyData({ policy: address(simpleGasPolicy), initData: policyInitData });

        PolicyData[] memory actionPolicyData = new PolicyData[](2);
        policyInitData = abi.encodePacked(uint128(block.timestamp + 1000), uint128(block.timestamp - 1));
        actionPolicyData[0] = PolicyData({ policy: address(timeFramePolicy), initData: policyInitData });
        policyInitData = abi.encodePacked(uint256(5 * 1e22));
        actionPolicyData[1] = PolicyData({ policy: address(valueLimitPolicy), initData: policyInitData });
        ActionId actionId = ActionId.wrap(keccak256(abi.encodePacked(address(target), MockTarget.setValue.selector)));
        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({ actionId: actionId, actionPolicies: actionPolicyData });

        enableData = EnableSessions({
            isigner: ISigner(address(simpleSigner)),
            isignerInitData: abi.encodePacked(sessionSigner2.addr),
            userOpPolicies: userOpPolicyData,
            erc1271Policies: new PolicyData[](0),
            actions: actions,
            permissionEnableSig: ""
        });

        // sign enableData hash
        bytes32 hash =
            smartSession.getDigest(enableData.isigner, instance.account, enableData, SmartSessionMode.UNSAFE_ENABLE);
        enableData.permissionEnableSig = abi.encodePacked(address(mockK1), sign(hash, owner.key));
    }
}
