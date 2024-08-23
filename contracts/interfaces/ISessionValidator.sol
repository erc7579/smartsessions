// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.23;

import "forge-std/interfaces/IERC165.sol";

interface ISessionValidator is IERC165 {
    function validateSignatureWithData(
        bytes32 hash,
        bytes calldata sig,
        bytes calldata data
    )
        external
        view
        returns (bool validSig);
}
