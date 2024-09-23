// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "./DataTypes.sol";
import { EIP712 } from "solady/utils/EIP712.sol";
import { ERC7579FallbackBase } from "@rhinestone/module-bases/src/ERC7579FallbackBase.sol";
import { IERC7579Account } from "erc7579/interfaces/IERC7579Account.sol";
import { AccountIdLib } from "./lib/AccountIdLib.sol";

contract SmartSessionCompatibilityFallback is ERC7579FallbackBase {
    using AccountIdLib for string;

    mapping(address smartAccount => bool isInitialized) public isInitialized;

    function onInstall(bytes calldata /*data*/ ) external override {
        isInitialized[msg.sender] = true;
    }

    function onUninstall(bytes calldata /*data*/ ) external override {
        isInitialized[msg.sender] = false;
    }

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        // if SmartSessions is to be used as a ERC1271/ERC7739 validator module, the account has to implement  function
        // supportsNestedTypedDataSign() public view virtual returns (bytes32 result)
        // this can be achieved by adding this function selector in your 7579 account as a fallback handler
        // YOU MUST NOT add any of the write functions via 7579 fallback selector
        if (typeID == ERC7579_MODULE_TYPE_FALLBACK) return true;
    }

    /// @dev For automatic detection that the smart account supports the nested EIP-712 workflow.
    /// By default, it returns `bytes32(bytes4(keccak256("supportsNestedTypedDataSign()")))`,
    /// denoting support for the default behavior, as implemented in
    /// `_erc1271IsValidSignatureViaNestedEIP712`, which is called in `isValidSignature`.
    /// Future extensions should return a different non-zero `result` to denote different behavior.
    /// This method intentionally returns bytes32 to allow freedom for future extensions.
    function supportsNestedTypedDataSign() public view virtual returns (bytes32 result) {
        result = bytes4(0xd620c85a);
    }

    function eip712Domain()
        public
        view
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        )
    {
        fields = hex"0f"; // 01111
        verifyingContract = msg.sender;

        // follows "vendorname.accountname.semver" structure as per ERC-7579
        string memory accountId = IERC7579Account(msg.sender).accountId();

        //parse name from accountId
        (name, version) = accountId.parseAccountId();

        chainId = block.chainid;
    }
}
