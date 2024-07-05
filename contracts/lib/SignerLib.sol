import "../DataTypes.sol";
import "../interfaces/ISigner.sol";
import { ERC7579ValidatorBase } from "modulekit/Modules.sol";
import "forge-std/console2.sol";

library SignerLib {
    bytes4 internal constant EIP1271_SUCCESS = 0x1626ba7e;

    error SignerNotFound(SignerId signerId, address account);
    error InvalidSessionKeySignature(SignerId signerId, ISigner isigner, address account, bytes32 userOpHash);

    function requireValidISigner(
        mapping(SignerId => mapping(address => ISigner)) storage $isigners,
        bytes32 userOpHash,
        address account,
        SignerId signerId,
        bytes calldata signature
    )
        internal
        view
    {
        ISigner isigner = $isigners[signerId][account];
        if (address(isigner) == address(0)) revert SignerNotFound(signerId, account);

        // check signature of ISigner first.
        // policies only need to be processed if the signature is correct
        if (
            isigner.checkSignature({ signerId: sessionId(signerId), sender: account, hash: userOpHash, sig: signature })
                != EIP1271_SUCCESS
        ) revert InvalidSessionKeySignature(signerId, isigner, account, userOpHash);
    }
}
