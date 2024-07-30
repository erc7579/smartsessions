// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { ModuleType, IRegistry } from "contracts/interfaces/IRegistry.sol";

contract MockRegistry is IRegistry {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*          Check with Registry internal attesters            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
    function check(address module) external view {
        if (module == address(0x420)) {
            revert();
        }
    }

    function checkForAccount(address smartAccount, address module) external view {
        if (module == address(0x420)) {
            revert();
        }
    }

    function check(address module, ModuleType moduleType) external view {
        if (module == address(0x420)) {
            revert();
        }
    }

    function checkForAccount(address smartAccount, address module, ModuleType moduleType) external view {
        if (module == address(0x420)) {
            revert();
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*              Check with external attester(s)               */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function check(address module, address[] calldata attesters, uint256 threshold) external view {
        if (module == address(0x420)) {
            revert();
        }
    }

    function check(
        address module,
        ModuleType moduleType,
        address[] calldata attesters,
        uint256 threshold
    )
        external
        view
    {
        if (module == address(0x420)) {
            revert();
        }
    }

    function trustAttesters(uint8 threshold, address[] calldata attesters) external { }
}
