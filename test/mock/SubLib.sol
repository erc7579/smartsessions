
// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "contracts/DataTypes.sol";

library SubLib {
    error DataTooShort(uint256 length);

    function parseInstallData(bytes calldata data) internal pure returns (ConfigId, address, bytes calldata) {
        if (data.length < 52) revert DataTooShort(data.length);
        return (ConfigId.wrap(bytes32(data[0:32])), address(bytes20(data[32:52])), data[52:]);
    }
}
