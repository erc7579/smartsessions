import "../Base.t.sol";
import "contracts/SmartSessionBase.sol";
import "solady/utils/ECDSA.sol";

contract Multichain712DigestTest is BaseTest {
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using EncodeLib for *;
    using HashLib for *;

    function setUp() public virtual override {
        super.setUp();
    }

    function test_multichain_digest_creation() public {

        Session memory session = Session({
            isigner: ISigner(address(yesSigner)),
            salt: keccak256("salt"),
            isignerInitData: "mockInitData",
            userOpPolicies: _getEmptyPolicyDatas(address(yesPolicy)),
            erc7739Policies: _getEmptyERC7739Data("mockContent", _getEmptyPolicyDatas(address(yesPolicy))),
            actions: _getEmptyActionDatas(ActionId.wrap(bytes32(uint256(1))), address(yesPolicy))
        });

        // predict signerId correlating to EnableSessions
        SignerId signerId = smartSession.getSignerId(session);

        
        // Make sessionsAndChainIds

        uint64[] memory chainIds = new uint64[](3); 
        chainIds[0] = 1855;
        chainIds[1] = uint64(block.chainid);
        chainIds[2] = 181818;
        uint256[] memory nonces = new uint256[](3);
        nonces[0] = smartSession.getNonce(signerId, instance.account);
        nonces[1] = nonces[0];
        nonces[2] = nonces[0];
        SmartSessionMode[] memory modes = new SmartSessionMode[](3);
        modes[0] = SmartSessionMode.UNSAFE_ENABLE;
        modes[1] = SmartSessionMode.UNSAFE_ENABLE;
        modes[2] = SmartSessionMode.UNSAFE_ENABLE;

        ChainSession[] memory sessionsAndChainIds = new ChainSession[](3);
        ChainDigest[] memory hashesAndChainIds = new ChainDigest[](3);

        for(uint i = 0; i < 3; i++) {
            ChainSession memory chainSession = ChainSession({
                chainId: chainIds[i],
                session: session
            });
            sessionsAndChainIds[i] = chainSession;

            bytes32 digest = session.sessionDigest(modes[i], nonces[i]);
            ChainDigest memory chainDigest = ChainDigest({
                chainId: chainIds[i],
                sessionDigest: digest
            });
            hashesAndChainIds[i] = chainDigest;
        }

        MultiChainSession memory multiChainSession = MultiChainSession({
            sessionsAndChainIds: sessionsAndChainIds
        });

        bytes32 fullHash = multiChainSession.multichainDigest(modes, nonces);
        bytes32 mimicHash = hashesAndChainIds.multichainDigest();

        assertEq(fullHash, mimicHash);
    }
}
