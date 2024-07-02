import "../DataTypes.sol";
import "../interfaces/ISigner.sol";
import { ERC7579ValidatorBase } from "modulekit/Modules.sol";

library SignerLib {
    bytes4 internal constant EIP1271_SUCCESS = 0x1626ba7e;

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

        // check signature of ISigner first.
        // policies only need to be processed if the signature is correct
        if (
            isigner.checkSignature({ signerId: signerId, sender: account, hash: userOpHash, sig: signature })
                != EIP1271_SUCCESS
        ) revert();
    }
}
