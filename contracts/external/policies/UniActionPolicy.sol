// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import "../../interfaces/IPolicy.sol";
import "../../lib/SubModuleLib.sol";

/**
 * @title UniActionPolicy: Universal Action Policy
 * @dev A policy that allows defining custom rules for actions based on function signatures.
 * Rules can be configured for function arguments with conditions.
 * So the argument is compared to a reference value against the the condition.
 * Also, rules feature usage limits for arguments.
 * For example, you can limit not just max amount for a transfer,
 * but also limit the total amount to be transferred within a permission.
 * Limit is uint256 so you can control any kind of numerable params.
 *
 * If you need to deal with dynamic-length arguments, such as bytes, please refer to
 * https://docs.soliditylang.org/en/v0.8.24/abi-spec.html#function-selector-and-argument-encoding
 * to learn more about how dynamic arguments are represented in the calldata
 * and which offsets should be used to access them.
 */
struct ActionConfig {
    uint256 valueLimitPerUse;
    ParamRules paramRules;
}

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
    NOT_EQUAL,
    IN_RANGE
}

contract UniActionPolicy is IActionPolicy {
    enum Status {
        NA,
        Live,
        Deprecated
    }

    using SubModuleLib for bytes;
    using UniActionLib for *;

    mapping(address msgSender => mapping(address opSender => uint256)) public usedIds;
    mapping(ConfigId id => mapping(address msgSender => mapping(address userOpSender => Status))) public status;
    mapping(ConfigId id => mapping(address msgSender => mapping(address userOpSender => ActionConfig))) public
        actionConfigs;

    /**
     * @dev Checks if the action is allowed based on the args rules defined in the policy.
     */
    function checkAction(
        ConfigId id,
        address account,
        address,
        uint256 value,
        bytes calldata data
    )
        external
        returns (uint256)
    {
        require(status[id][msg.sender][account] == Status.Live);
        ActionConfig storage config = actionConfigs[id][msg.sender][account];
        require(value <= config.valueLimitPerUse);
        uint256 length = config.paramRules.length;
        for (uint256 i = 0; i < length; i++) {
            if (!config.paramRules.rules[i].check(data)) return VALIDATION_FAILED;
        }

        return VALIDATION_SUCCESS;
    }

    function _initPolicy(ConfigId id, address mxer, address opSender, bytes calldata _data) internal {
        usedIds[mxer][opSender]++;
        status[id][mxer][opSender] = Status.Live;
        ActionConfig memory config = abi.decode(_data, (ActionConfig));
        actionConfigs[id][mxer][opSender].fill(config);
    }

    function _deinitPolicy(ConfigId id, address mxer, address opSender, bytes calldata) internal {
        status[id][mxer][opSender] = Status.Deprecated;
        usedIds[mxer][opSender]--;
    }

    // to be used use when the policy is installed directly to the SA
    // requires state is fresh clean
    // even cleaning with onUninstall is not enough, as it sets Status.deprecated, not Status.NA
    // recommended to use fresh id in this case
    function onInstall(bytes calldata data) external {
        (ConfigId id, bytes calldata _data) = data.parseInstallData();
        require(status[id][msg.sender][msg.sender] == Status.NA);
        _initPolicy(id, msg.sender, msg.sender, _data);
    }

    // to be used use when the policy is installed directly to the SA
    // overwrites state
    function initializeWithMultiplexer(address account, ConfigId configId, bytes calldata initData) external {
        _initPolicy(configId, msg.sender, account, initData);
    }

    // to be used use when the policy is installed directly to the SA
    function onUninstall(bytes calldata data) external {
        (ConfigId id, bytes calldata _data) = data.parseInstallData();
        require(status[id][msg.sender][msg.sender] == Status.Live);
        _deinitPolicy(id, msg.sender, msg.sender, _data);
    }

    function isInitialized(address account) external view returns (bool) {
        return usedIds[msg.sender][account] > 0;
    }

    function isInitialized(address mxer, address account) external view returns (bool) {
        return usedIds[mxer][account] > 0;
    }

    function isInitialized(address account, ConfigId id) external view returns (bool) {
        return status[id][msg.sender][account] == Status.Live;
    }

    function isInitialized(address mxer, address account, ConfigId id) external view returns (bool) {
        return status[id][mxer][account] == Status.Live;
    }

    function isModuleType(uint256 id) external pure returns (bool) {
        return id == ERC7579_MODULE_TYPE_POLICY;
    }

    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return true;
    }
}

library UniActionLib {
    /**
     * @dev parses the function arg from the calldata based on the offset
     * and compares it to the reference value based on the condition.
     * Also checks if the limit is reached/exceeded.
     */
    function check(ParamRule storage rule, bytes calldata data) internal returns (bool) {
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
        } else if (rule.condition == ParamCondition.IN_RANGE) {
            // in this case rule.ref is abi.encodePacked(uint128(min), uint128(max))
            if (param < (rule.ref >> 128) || param > (rule.ref & 0x00000000000000000000000000000000ffffffffffffffffffffffffffffffff)) {
                return false;
            }
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
        $config.valueLimitPerUse = config.valueLimitPerUse;
        $config.paramRules.length = config.paramRules.length;
        for (uint256 i; i < config.paramRules.length; i++) {
            $config.paramRules.rules[i] = config.paramRules.rules[i];
        }
    }
}

/**
 * Further development:
 *
 *   - Add compound value limit.
 *     struct ActionConfig {
 *         uint256 valueLimitPerUse;
 *         uint256 totalValueLimit;
 *         uint256 valueUsed;
 *         ParamRules paramRules;
 *     }
 *
 *     - Add param relations.
 *
 *     Add this to ActionConfig => Relation[] paramRelations;
 *         struct Relation {
 *             address verifier;
 *             bytes4 selector;
 *             bytes1 argsAmount;
 *             uint64[4] offsets;
 *             bytes32 context;
 *         }
 *     Add checking for relations.
 */
