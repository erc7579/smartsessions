// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "../DataTypes.sol";
import "forge-std/console2.sol";

library SubLib {
    error DataTooShort(uint256 length);
    error InvalidSessionKeySignature(SignerId signerId, ISigner isigner, address account, bytes32 userOpHash);

    function parseInstallData(bytes calldata data)
        internal
        view returns (SessionId, address, bytes calldata)
    {
        if(data.length < 52) revert DataTooShort(data.length);
        return(
            SessionId.wrap(bytes32(data[0:32])),
            address(bytes20(data[32:52])),
            data[52:]
        );
    }
}
