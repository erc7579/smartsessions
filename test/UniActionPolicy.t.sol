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
import { MockTarget } from "./mock/MockTarget.sol";
import { SimpleSigner } from "./mock/SimpleSigner.sol";
import { SimpleGasPolicy } from "./mock/SimpleGasPolicy.sol";
import { TimeFramePolicy } from "./mock/TimeFramePolicy.sol";
import { EIP1271_MAGIC_VALUE, IERC1271 } from "module-bases/interfaces/IERC1271.sol";
import { MockK1Validator } from "test/mock/MockK1Validator.sol";
import { UserOperationBuilder } from "contracts/erc7679/UserOpBuilder.sol";
import { ModeLib, ModeCode as ExecutionMode } from "erc7579/lib/ModeLib.sol";
import { IRegistry } from "contracts/interfaces/IRegistry.sol";
import { MockRegistry } from "./mock/MockRegistry.sol";
import "./mock/UniActionPolicy.sol";

import "forge-std/console2.sol";

IRegistry constant registry = IRegistry(0x0000000000E23E0033C3e93D9D4eBc2FF2AB2AEF);

contract UniversalActionPolicyTest is RhinestoneModuleKit, Test {
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using EncodeLib for SignerId;

    // account and modules
    AccountInstance internal instance;
    MockK1Validator internal mockK1;
    SmartSession internal smartSession;
    SimpleSigner internal simpleSigner;
    SimpleGasPolicy internal simpleGasPolicy;
    TimeFramePolicy internal timeFramePolicy;
    UniActionPolicy internal uniPolicy;
    MockCallee internal mockCallee;

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

        defaultSigner1 = SignerId.wrap(bytes32(hex"01"));
        defaultSigner2 = SignerId.wrap(bytes32(hex"02"));
        defaultSigner2 = SignerId.wrap(bytes32(hex"02"));

        smartSession = new SmartSession();
        target = new MockTarget();
        simpleSigner = new SimpleSigner();
        simpleGasPolicy = new SimpleGasPolicy();
        timeFramePolicy = new TimeFramePolicy();
        uniPolicy = new UniActionPolicy();
        mockCallee = new MockCallee();

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

    function test_use_Universal_Action_Policy() public {
        uint256 valToAdd = 2517;
        bytes32 valToAdd32 = bytes32(uint256(0xdecaf));
        (uint256 prevBal, bytes32 prevBal32) = mockCallee.bals(instance.account);
        assertEq(prevBal, 0);
        assertEq(prevBal32, 0);

        // Enable Uni Action Policy Permission
        _preEnablePermissions();

        UserOpData memory userOpData = instance.getExecOps({
            target: address(mockCallee),
            value: 0,
            callData: abi.encodeCall(MockCallee.addBalance, (instance.account, valToAdd, valToAdd32)),
            txValidator: address(smartSession)
        });

        bytes memory sig = sign(userOpData.userOpHash, sessionSigner1.key);
        userOpData.userOp.signature = EncodeLib.encodeUse({ signerId: defaultSigner1, sig: sig });
        userOpData.execUserOps();

        (uint256 postBal, bytes32 postBal32) = mockCallee.bals(instance.account);
        assertEq(postBal, valToAdd);
        assertEq(postBal32, valToAdd32);
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

        // enable timeframe policy as userOpPolicy
        policyInitData = abi.encodePacked(uint128(block.timestamp + 1000), uint128(block.timestamp - 1));
        policyData[0] = PolicyData({ policy: address(timeFramePolicy), initData: policyInitData });
        smartSession.enableUserOpPolicies(defaultSigner1, policyData);

        // enable action policies
        PolicyData[] memory actionPolicyData = new PolicyData[](2);
        ActionId actionId =
            ActionId.wrap(keccak256(abi.encodePacked(address(mockCallee), MockCallee.addBalance.selector)));

        // use timeframe for action as well with narrower limit
        policyInitData = abi.encodePacked(uint128(block.timestamp + 500), uint128(block.timestamp - 1));
        actionPolicyData[0] = PolicyData({ policy: address(timeFramePolicy), initData: policyInitData });

        //use UniAction Policy
        ParamRule memory addrRule = ParamRule({
            condition: ParamCondition.EQUAL,
            offset: 0x00,
            isLimited: false,
            ref: bytes32(bytes20(instance.account)) >> 96,
            usage: LimitUsage({ limit: 0, used: 0 })
        });
        ParamRule memory uint256Rule = ParamRule({
            condition: ParamCondition.LESS_THAN,
            offset: 0x20,
            isLimited: true,
            ref: bytes32(uint256(1e30)),
            usage: LimitUsage({ limit: 1e32, used: 0 })
        });
        ParamRule memory bytes32Rule = ParamRule({
            condition: ParamCondition.GREATER_THAN,
            offset: 0x40,
            isLimited: false,
            ref: bytes32(uint256(0x01)),
            usage: LimitUsage({ limit: 0, used: 0 })
        });
        ParamRule[16] memory rules;
        rules[0] = addrRule;
        rules[1] = uint256Rule;
        rules[2] = bytes32Rule;
        ParamRules memory paramRules = ParamRules({ length: 3, rules: rules });
        ActionConfig memory config = ActionConfig({ valueLimit: 1e21, paramRules: paramRules });
        policyInitData = abi.encode(config);

        actionPolicyData[1] = PolicyData({ policy: address(uniPolicy), initData: policyInitData });

        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({ actionId: actionId, actionPolicies: actionPolicyData });
        smartSession.enableActionPolicies(defaultSigner1, actions);
        vm.stopPrank();
    }
}

contract MockCallee {
    struct Balances {
        uint256 uintBalance;
        bytes32 bytes32Balance;
    }

    mapping(address => Balances) public bals;

    function addBalance(address addrParam, uint256 uintParam, bytes32 bytesParam) external {
        bals[addrParam].uintBalance += uintParam;

        bals[addrParam].bytes32Balance = bytes32(uint256(bals[addrParam].bytes32Balance) + uint256(bytesParam));
    }
}
