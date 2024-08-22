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

IRegistry constant registry = IRegistry(0x000000000069E2a187AEFFb852bF3cCdC95151B2);

contract BaseTest is RhinestoneModuleKit, Test {
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using EncodeLib for SignerId;

    // account and modules
    MockK1Validator internal mockK1;
    AccountInstance internal instance;
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

    function setUp() public virtual {
        instance = makeAccountInstance("smartaccount");
        mockK1 = new MockK1Validator();

        IRegistry _registry = IRegistry(address(new MockRegistry()));
        vm.etch(address(registry), address(_registry).code);

        owner = makeAccount("owner");
        sessionSigner1 = makeAccount("sessionSigner1");
        sessionSigner2 = makeAccount("sessionSigner2");

        smartSession = new SmartSession(0);
        target = new MockTarget();
        yesSigner = new YesSigner();
        yesPolicy = new YesPolicy();
        simpleSigner = new SimpleSigner();
        simpleGasPolicy = new SimpleGasPolicy();
        timeFramePolicy = new TimeFramePolicy();
        valueLimitPolicy = new ValueLimitPolicy();

        instance.installModule({
            moduleTypeId: MODULE_TYPE_VALIDATOR,
            module: address(mockK1),
            data: abi.encodePacked(owner.addr)
        });

        EnableSessions[] memory installData = new EnableSessions[](0);
        instance.installModule({
            moduleTypeId: MODULE_TYPE_VALIDATOR,
            module: address(smartSession),
            data: abi.encode(installData)
        });
    }

    function sign(bytes32 hash, uint256 privKey) internal pure returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, hash);
        // Set the signature
        signature = abi.encodePacked(r, s, v);
    }

    function _getEmptyPolicyData(address policyContract) internal pure returns (PolicyData memory) {
        return PolicyData({ policy: policyContract, initData: "" });
    }

    function _getEmptyPolicyDatas(address policyContract) internal pure returns (PolicyData[] memory policyDatas) {
        policyDatas = new PolicyData[](1);
        policyDatas[0] = _getEmptyPolicyData(policyContract);
    }

    function _getEmptyActionData(ActionId actionId, address policyContract) internal pure returns (ActionData memory) {
        return ActionData({ actionId: actionId, actionPolicies: _getEmptyPolicyDatas(policyContract) });
    }

    function _getEmptyActionDatas(
        ActionId actionId,
        address policyContract
    )
        internal
        pure
        returns (ActionData[] memory actionDatas)
    {
        actionDatas = new ActionData[](1);
        actionDatas[0] = _getEmptyActionData(actionId, policyContract);
    }

    function _getEmptyERC7739Data(
        string memory content,
        PolicyData[] memory erc1271Policies
    )
        internal
        returns (ERC7739Data memory)
    {
        string[] memory contents = new string[](1);
        contents[0] = content;
        return ERC7739Data({ allowedERC7739Content: contents, erc1271Policies: erc1271Policies });
    }

    function _makeMultiChainEnableData(
        SignerId signerId,
        Session memory session,
        AccountInstance memory instance,
        SmartSessionMode mode
    )
        internal
        view
        returns (EnableSessions memory enableData)
    {
        enableData = EnableSessions({
            sessionIndex: 1,
            hashesAndChainIds: "",
            sessionToEnable: session,
            permissionEnableSig: ""
        });

        bytes32 sessionDigest =
            smartSession.getDigest({ signerId: signerId, account: instance.account, data: session, mode: mode });

        enableData.hashesAndChainIds = EncodeLib.encodeHashesAndChainIds(
            Solarray.uint64s(181_818, uint64(block.chainid)), Solarray.bytes32s(sessionDigest, sessionDigest)
        );
    }

    // function _enable_exec(
    //     EnableSessions memory enableSessions,
    //     address target,
    //     uint256 value,
    //     bytes calldata callData
    // )
    //     internal
    // {
    //     // get userOp from ModuleKit
    //     UserOpData memory userOpData = instance.getExecOps({
    //         target: target,
    //         value: value,
    //         callData: callData,
    //         txValidator: address(smartSession)
    //     });
    //
    //     // predict signerId correlating to EnableSessions
    //     SignerId signerId = smartSession.getSignerId(enableSessions.isigner, enableSessions.isignerInitData);
    //
    //     bytes32 hash =
    //         smartSession.getDigest(enableData.isigner, instance.account, enableData, SmartSessionMode.UNSAFE_ENABLE);
    // }
}
