import "forge-std/Test.sol";
import "contracts/lib/HashLib.sol";
import "contracts/DataTypes.sol";

contract Helper {
    using HashLib for *;

    function hash(Session memory session, address smartSession) public returns (bytes32 hash) {
        hash = session._sessionDigest({
            account: address(0x6605F8785E09a245DD558e55F9A0f4A508434503),
            mode: SmartSessionMode.ENABLE,
            smartSession: smartSession
        });
    }
}

contract EIP712Test is Test {
    using HashLib for *;

    Helper helper;

    function setUp() public {
        helper = new Helper();
        address helperAddr = address(0x6605F8785E09a245DD558e55F9A0f4A508434503);
        vm.etch(helperAddr, address(helper).code);
        helper = Helper(helperAddr);
    }

    function test_type_notation() public {
        // bytes32 hash;

        string memory expectedSession =
            "SessionEIP712(address account,address smartSession,uint8 mode,address sessionValidator,bytes32 salt,bytes sessionValidatorInitData,PolicyData[] userOpPolicies,ERC7739Data erc7739Policies,ActionData[] actions)ActionData(bytes4 actionTargetSelector,address actionTarget,PolicyData[] actionPolicies)ERC7739Data(string[] allowedERC7739Content,PolicyData[] erc1271Policies)PolicyData(address policy,bytes initData)";
        bytes32 hash = keccak256(abi.encodePacked(expectedSession));
        assertEq(hash, SESSION_TYPEHASH);
    }

    function test_policy_hash() public {
        bytes32 expected_typehash = 0xdddac12cd8b10a071bea04226e97ac9490698394e19224abc47a5cfeeeb6ee97;
        assertEq(expected_typehash, POLICY_DATA_TYPEHASH);

        PolicyData memory policyData =
            PolicyData({ policy: address(0xf022051bEB9E8848e99f47D3eD1397CEEfBF3d4F), initData: "" });

        bytes32 hash = policyData.hashPolicyData();
        bytes32 expected_hash = 0x531c8f7eafebd3a565ad77225700ee7551c4c552b8e8a8417710ec2aa7990e9d;
        assertEq(hash, expected_hash);

        console2.logBytes(abi.encode(policyData));
    }

    function test_action_hash() public {
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(0xf022051bEB9E8848e99f47D3eD1397CEEfBF3d4F), initData: "" });

        ActionData memory actionData = ActionData({
            actionTarget: address(0x7227DCfB0c5EC7A5F539F97b18Be261C49687eD6),
            actionTargetSelector: bytes4(0x9cfd7cff),
            actionPolicies: policyDatas
        });

        bytes32 expected_typehash = 0x35809859dccf8877c407a59527c2f00fb81ca9c198ebcb0c832c3deaa38d3502;
        assertEq(expected_typehash, ACTION_DATA_TYPEHASH);
        bytes32 hash = actionData.hashActionData();
        bytes32 expected_hash = 0xe7fd3595c8793c559219f8cfb42f912d7e5f196fdc8db29bbdb718127fbed2e4;

        assertEq(hash, expected_hash);
    }

    function test_erc7739_hash() public {
        bytes32 expected_typehash = 0xdd8bf2f9b88fa557b2cb00ffd37dc4a3b8f3ff1d0d9e03c6f7c183f38869e91d;
        assertEq(expected_typehash, ERC7739_DATA_TYPEHASH);

        ERC7739Data memory erc7739Data =
            ERC7739Data({ allowedERC7739Content: new string[](0), erc1271Policies: new PolicyData[](0) });

        bytes32 hash = erc7739Data.hashERC7739Data();
        bytes32 expected_hash = 0x8c545c4d32b39dca5fd67d3d0e06888953f56f2061b24a1abd1b918ec92377d2;
        assertEq(hash, expected_hash);
    }

    function test_session_hash() public {
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(0xf022051bEB9E8848e99f47D3eD1397CEEfBF3d4F), initData: "" });

        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({
            actionTarget: address(0x7227DCfB0c5EC7A5F539F97b18Be261C49687eD6),
            actionTargetSelector: bytes4(0x9cfd7cff),
            actionPolicies: policyDatas
        });

        Session memory session = Session({
            sessionValidator: ISessionValidator(0x6605F8785E09a245DD558e55F9A0f4A508434503),
            sessionValidatorInitData: hex"0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000010000000000000000000000002dc2fb2f4f11dee1d6a2054ffcbf102d09b62be2",
            salt: bytes32(0x3200000000000000000000000000000000000000000000000000000000000000),
            userOpPolicies: new PolicyData[](0),
            erc7739Policies: ERC7739Data({ allowedERC7739Content: new string[](0), erc1271Policies: new PolicyData[](0) }),
            actions: actions
        });

        bytes32 expected_typehash = 0x284c8dba379f7e914afbc9f8af8cab0b36caa213e4633bf850e7ebbd1f31a438;
        assertEq(expected_typehash, SESSION_TYPEHASH, "typehash");

        bytes32 hash = helper.hash(session, address(0x6605F8785E09a245DD558e55F9A0f4A508434503));

        bytes32 expected_hash = 0x2ddf735a24b4b2a5866919f3de993e3b0e5481f67c08d98b8358f9bf9f749300;
        assertEq(hash, expected_hash, "hash fn borked");
    }
}
