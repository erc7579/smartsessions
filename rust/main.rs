mod types;
mod mock;

use crate::types::*;

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
use mock::mock_erc7739_data;
use serde::Serialize;


pub fn main() {
    let session = mock::mock_session();
    let account = address!("6605F8785E09a245DD558e55F9A0f4A508434503");
    let smart_session = address!("6605F8785E09a245DD558e55F9A0f4A508434503");
    let mode = 1;
    let signed_session = to_signed_session(session.clone(), account, smart_session, mode, U256::from(0));


    let chain_session = ChainSession {
        chainId: 1,
        session: signed_session.clone(),
    };

    let chain_digests:ChainDigest = chain_session.clone().into();

    let multi_chain_session = MultiChainSession {
        sessionsAndChainIds: vec![chain_session.clone()],
    };

    println!("TypeHashes");
    println!("SignedSession: {}", SignedSession::eip712_type_hash(&signed_session));
    println!("SignedPermissions: {}", SignedPermissions::eip712_type_hash(&signed_session.permissions));

    println!("Policy: {}", PolicyData::eip712_type_hash(&session.userOpPolicies[0]));
    println!("ERC7739Data: {}", ERC7739Data::eip712_type_hash(&session.erc7739Policies));
    println!("Actions: {}", ActionData::eip712_type_hash(&session.actions[0]));
    println!("ChainSession: {}", ChainSession::eip712_type_hash(&chain_session));
    println!("CHainDigest: {}", ChainDigest::eip712_type_hash(&chain_digests));
    println!("MultiChainSession: {}", MultiChainSession::eip712_type_hash(&multi_chain_session));

    let foo = mock_erc7739_data();
    println!("ERC7739Context: {}", ERC7739Context::eip712_type_hash(&foo.allowedERC7739Content[0]));

    println!("DataHashes");
    println!("ERC7739Context: {}", ERC7739Context::eip712_hash_struct(&foo.allowedERC7739Content[0]));
    println!("ERC7739Data: {}", ERC7739Data::eip712_hash_struct(&foo));


    println!("!SignedSession: {}", SignedSession::eip712_hash_struct(&signed_session));
    println!("!SignedPermission: {}", SignedPermissions::eip712_hash_struct(&signed_session.permissions));
    println!("Policy: {}", PolicyData::eip712_hash_struct(&session.userOpPolicies[0]));
    println!("ERC7739Data: {}", ERC7739Data::eip712_hash_struct(&session.erc7739Policies));

    println!("Root");
    println!("SignedSession: {}", SignedSession::eip712_root_type());
    println!("{:?}", SignedSession::eip712_components());
    println!("PolicyData: {}", PolicyData::eip712_root_type());
    println!("ActionData: {}", ActionData::eip712_root_type());
    println!("ERC7739Data: {}", ERC7739Data::eip712_root_type());
    println!("ERC7739Context: {}", ERC7739Context::eip712_root_type());
    println!("Chain_Session: {}", ChainSession::eip712_root_type());
    println!("MultiChainSession: {}", MultiChainSession::eip712_root_type());

}

