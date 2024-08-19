// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "contracts/interfaces/IPolicy.sol";
import "contracts/lib/SubLib.sol";

struct ActionConfig {
    uint256 valueLimit;
    // add valueUsed?
    ParamRules paramRules;
}
// Relation[] paramRelations; // TODO:

struct ParamRules {
    uint256 length;
    ParamRule[16] rules;
}

struct ParamRule {
    ParamCondition condition;
    uint64 offset;
    bool isLimited;
    bytes32 ref;
    LimitUsage usage;
}

struct LimitUsage {
    uint256 limit;
    uint256 used;
}

enum ParamCondition {
    EQUAL,
    GREATER_THAN,
    LESS_THAN,
    GREATER_THAN_OR_EQUAL,
    LESS_THAN_OR_EQUAL,
    NOT_EQUAL
}

/*
struct Relation {
    address verifier;
    bytes4 selector;
    bytes1 argsAmount;
    uint64[4] offsets;
    bytes32 context;
}
*/

contract UniActionPolicy is IActionPolicy {
    enum Status {
        NA,
        Live,
        Deprecated
    }

    using SubLib for bytes;
    using UniActionLib for *;

    mapping(address msgSender => mapping(address opSender => uint256)) public usedIds;
    mapping(SessionId id => mapping(address msgSender => mapping(address userOpSender => Status))) public status;
    mapping(SessionId id => mapping(address msgSender => mapping(address userOpSender => ActionConfig))) public
        actionConfigs;

    function checkAction(
        SessionId id,
        address,
        uint256 value,
        bytes calldata data,
        PackedUserOperation calldata op
    )
        external
        returns (uint256)
    {
        require(status[id][msg.sender][op.sender] == Status.Live);
        ActionConfig storage config = actionConfigs[id][msg.sender][op.sender];
        require(value <= config.valueLimit);
        ParamRule[16] memory rules = config.paramRules.rules;
        uint256 length = config.paramRules.length;
        for (uint256 i = 0; i < length; i++) {
            ParamRule memory rule = rules[i];
            if (!rule.check(data)) return VALIDATION_FAILED;
        }

        return VALIDATION_SUCCESS;
    }

    function _onInstallPolicy(SessionId id, address opSender, bytes calldata _data) internal {
        require(status[id][msg.sender][opSender] == Status.NA);
        usedIds[msg.sender][opSender]++;
        status[id][msg.sender][opSender] = Status.Live;
        ActionConfig memory config = abi.decode(_data, (ActionConfig));
        actionConfigs[id][msg.sender][opSender].fill(config);
    }

    function _onUninstallPolicy(SessionId id, address opSender, bytes calldata) internal {
        require(status[id][msg.sender][opSender] == Status.Live);
        status[id][msg.sender][opSender] = Status.Deprecated;
        usedIds[msg.sender][opSender]--;
    }

    function onInstall(bytes calldata data) external {
        (SessionId id, address opSender, bytes calldata _data) = data.parseInstallData();
        _onInstallPolicy(id, opSender, _data);
    }

    function onUninstall(bytes calldata data) external {
        (SessionId id, address opSender, bytes calldata _data) = data.parseInstallData();
        _onUninstallPolicy(id, opSender, _data);
    }

    function isInitialized(address account) external view returns (bool) {
        return usedIds[msg.sender][account] > 0;
    }

    function isInitialized(address mxer, address account) external view returns (bool) {
        return usedIds[mxer][account] > 0;
    }

    function isInitialized(address account, SessionId id) external view returns (bool) {
        return status[id][msg.sender][account] == Status.Live;
    }

    function isInitialized(address mxer, address account, SessionId id) external view returns (bool) {
        return status[id][mxer][account] == Status.Live;
    }

    function isModuleType(uint256 id) external pure returns (bool) {
        return id == 7;
    }

    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return true;
    }
}

library UniActionLib {
    function check(ParamRule memory rule, bytes calldata data) internal view returns (bool) {
        bytes32 param = bytes32(data[4 + rule.offset:4 + rule.offset + 32]);

        // CHECK ParamCondition
        if (rule.condition == ParamCondition.EQUAL && param != rule.ref) {
            return false;
        } else if (rule.condition == ParamCondition.GREATER_THAN && param <= rule.ref) {
            return false;
        } else if (rule.condition == ParamCondition.LESS_THAN && param >= rule.ref) {
            return false;
        } else if (rule.condition == ParamCondition.GREATER_THAN_OR_EQUAL && param < rule.ref) {
            return false;
        } else if (rule.condition == ParamCondition.LESS_THAN_OR_EQUAL && param > rule.ref) {
            return false;
        } else if (rule.condition == ParamCondition.NOT_EQUAL && param == rule.ref) {
            return false;
        }

        // CHECK PARAM LIMIT
        if (rule.isLimited) {
            if (rule.usage.used + uint256(param) > rule.usage.limit) {
                return false;
            }
            rule.usage.used += uint256(param);
        }
        return true;
    }

    function fill(ActionConfig storage $config, ActionConfig memory config) internal {
        $config.valueLimit = config.valueLimit;
        $config.paramRules.length = config.paramRules.length;
        for (uint256 i; i < config.paramRules.length; i++) {
            $config.paramRules.rules[i] = config.paramRules.rules[i];
        }
    }
}
