
use alloy::{
    dyn_abi::SolType,
    primitives::{address, b256, bytes, fixed_bytes, keccak256, Bytes, U256},
    signers::{local::PrivateKeySigner, Signer},
    sol,
    sol_types::{eip712_domain, SolStruct},
};

use hex;
use clap::{App, Arg, SubCommand};
use eyre::Result;
use serde::Serialize;

sol! {
    #[allow(missing_docs)]
    #[derive(Serialize)]
    struct EnableSession {
        uint8 chainDigestIndex;
        ChainDigest[] hashesAndChainIds;
        SessionConf sessionToEnable;
        bytes permissionEnableSig;
    }

    #[allow(missing_docs)]
    #[derive(Serialize)]
    struct ChainDigest {
        uint64 chainId;
        bytes32 sessionDigest;
    }

    #[allow(missing_docs)]
    #[derive(Serialize)]
    struct SessionConf {
        address sessionValidator;
        bytes sessionValidatorInitData;
        bytes32 salt;
        PolicyData[] userOpPolicies;
        ERC7739Data erc7739Policies;
        ActionData[] actions;
    }


    #[allow(missing_docs)]
    #[derive(Serialize)]
    struct PolicyData {
        address policy;
        bytes initData;
    }

    #[allow(missing_docs)]
    #[derive(Serialize)]
    struct ActionData {
        bytes4 actionTargetSelector;
        address actionTarget;
        PolicyData[] actionPolicies;
    }

    #[allow(missing_docs)]
    #[derive(Serialize)]
    struct ERC7739Data {
        string[] allowedERC7739Content;
        PolicyData[] erc1271Policies;
    }
}

sol! {

    #[allow(missing_docs)]
    #[derive(Serialize)]
    struct SessionEIP712 {
        address account;
        address smartSession;
        uint8 mode;
        address sessionValidator;
        bytes32 salt;
        bytes sessionValidatorInitData;
        PolicyData[] userOpPolicies;
        ERC7739Data erc7739Policies;
        ActionData[] actions;
        uint256 nonce;
    }

    #[allow(missing_docs)]
    #[derive(Serialize)]
    struct ChainSessionEIP712 {
        uint64 chainId;
        SessionEIP712 session;
    }

    #[allow(missing_docs)]
    #[derive(Serialize)]
    struct MultiChainSessionEIP712 {
        ChainSessionEIP712[] sessionsAndChainIds;
    }

}

fn get_policy() {
    let data = PolicyData {
        policy: address!("f022051bEB9E8848e99f47D3eD1397CEEfBF3d4F"),
        initData: bytes!(""),
    };

    // // let encoded =bytes!("0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000f022051beb9e8848e99f47d3ed1397ceefbf3d4f00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000");
    //
    // let data = PolicyData::abi_decode(&param, true).unwrap();

    println!("policy type: {:?}", data.eip712_type_hash());
    println!("policy data: {:?}", data.eip712_hash_struct());

}

fn get_action() {
    let action = ActionData {
        actionTarget: address!("7227dcfb0c5ec7a5f539f97b18be261c49687ed6"),
        actionTargetSelector: fixed_bytes!("9cfd7cff"),
        actionPolicies: vec![PolicyData {
            policy: address!("f022051bEB9E8848e99f47D3eD1397CEEfBF3d4F"),
            initData: bytes!(""),
        }],
    };

    println!("action type: {:?}", action.eip712_type_hash());
    println!("action data: {:?}", action.eip712_hash_struct());
}

fn get_erc7739() {
    let erc7739 = ERC7739Data {
        allowedERC7739Content: vec![],
        erc1271Policies: vec![],
    };

    println!("erc7739 type: {:?}", erc7739.eip712_type_hash());
    println!("erc7739 data: {:?}", erc7739.eip712_hash_struct());
}

fn get_session() {
    let data = PolicyData {
        policy: address!("f022051bEB9E8848e99f47D3eD1397CEEfBF3d4F"),
        initData: bytes!(""),
    };
    let session = SessionEIP712 {
        sessionValidator: address!("6605F8785E09a245DD558e55F9A0f4A508434503"),
        sessionValidatorInitData: bytes!("0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000010000000000000000000000002dc2fb2f4f11dee1d6a2054ffcbf102d09b62be2"),
        salt: b256!("3200000000000000000000000000000000000000000000000000000000000000"),
        userOpPolicies: vec![],
        erc7739Policies: ERC7739Data {
            allowedERC7739Content: vec![],
            erc1271Policies: vec![],
        },
        actions: vec![ActionData {
            actionTarget: address!("7227dcfb0c5ec7a5f539f97b18be261c49687ed6"),
            actionTargetSelector: fixed_bytes!("9cfd7cff"),
            actionPolicies: vec![data],
        }],
        account: address!("6605F8785E09a245DD558e55F9A0f4A508434503"),
        mode: 1,
        nonce: U256::from(0),
        smartSession: address!("6605F8785E09a245DD558e55F9A0f4A508434503"),
    };

    println!("session712 type: {:?}", session.eip712_type_hash());
    println!("session712 data: {:?}", session.eip712_hash_struct());
}

 fn main() {

    // let domain = eip712_domain! {
    //     name: "Uniswap V2",
    //     version: "1",
    //     chain_id: 1,
    //     verifying_contract: address!("B4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc"),
    //     salt: keccak256("test")
    // };

    get_policy();
    get_action();
    get_erc7739();
    get_session();


    println!("{:?}", SessionEIP712::eip712_root_type());
    println!("{:?}", SessionEIP712::eip712_components());
    println!("encode data: {:?}", SessionEIP712::eip712_encode_type());

}



