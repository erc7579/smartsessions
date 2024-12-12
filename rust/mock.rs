use crate::types::*;

use alloy::{
    dyn_abi::SolType,
    primitives::{Address, address, b256, bytes, fixed_bytes, FixedBytes, keccak256, Bytes, U256},
    signers::{local::PrivateKeySigner, Signer},
    sol,
    sol_types::{eip712_domain, SolStruct},
};

pub fn mock_policy_data() -> PolicyData {
    PolicyData {
        policy: Address::ZERO,
        initData: Bytes::default(),
    }
}

pub fn mock_action_data() -> ActionData {
    ActionData {
        actionTargetSelector: FixedBytes::<4>::default(),
        actionTarget: Address::ZERO,
        actionPolicies: vec![mock_policy_data()],
    }
}

pub fn mock_erc7739_context() -> ERC7739Context {

    let app_domain_sep = fixed_bytes!("506da236a69b2f437f547d7900eb350f6a4cb145b6b850a499f29954b24c5739");
    ERC7739Context {
        appDomainSeparator: app_domain_sep,
        contentName: vec!["mockContent".to_string()]
    }
}

pub fn mock_erc7739_data() -> ERC7739Data {
    ERC7739Data {
        allowedERC7739Content: vec![mock_erc7739_context()],
        erc1271Policies: vec![mock_policy_data()],
    }
}


pub fn mock_session() -> Session {
    Session {
        sessionValidator: Address::ZERO,
        sessionValidatorInitData: Bytes::default(),
        salt: FixedBytes::<32>::default(),
        userOpPolicies: vec![mock_policy_data()],
        erc7739Policies: mock_erc7739_data(),
        actions: vec![mock_action_data()],
        permitERC4337Paymaster: true
    }
}

