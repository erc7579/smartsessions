// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "../DataTypes.sol";

library SmartSessionModeLib {
    function isUseMode(SmartSessionMode mode) internal pure returns (bool) {
        if (mode == SmartSessionMode.USE) {
            return true;
        }
        return false;
    }

    function isEnableMode(SmartSessionMode mode) internal pure returns (bool) {
        if (
            mode == SmartSessionMode.ENABLE || mode == SmartSessionMode.UNSAFE_ENABLE
                || mode == SmartSessionMode.ENABLE_ADD_POLICIES || mode == SmartSessionMode.UNSAFE_ENABLE_ADD_POLICIES
        ) {
            return true;
        }
        return false;
    }

    function enableSessionValidator(SmartSessionMode mode) internal pure returns (bool) {
        if (mode == SmartSessionMode.ENABLE || mode == SmartSessionMode.UNSAFE_ENABLE) {
            return true;
        }
        return false;
    }

    function useRegistry(SmartSessionMode mode) internal pure returns (bool) {
        if (mode == SmartSessionMode.ENABLE || mode == SmartSessionMode.ENABLE_ADD_POLICIES) {
            return true;
        }
        return false;
    }
}
