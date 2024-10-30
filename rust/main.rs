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
    let signed_session = to_signedSession(session.clone(), account, smart_session, mode, U256::from(0));

    println!("TypeHashes");
    println!("SignedSession: {}", SignedSession::eip712_type_hash(&signed_session));

    println!("Policy: {}", PolicyData::eip712_type_hash(&session.userOpPolicies[0]));
    println!("ERC7739Data: {}", ERC7739Data::eip712_type_hash(&session.erc7739Policies));

    let foo = mock_erc7739_data();
    println!("EIP712Domain: {}", EIP712Domain::eip712_type_hash(&foo.allowedERC7739Content[0].appDomainSeparator));
    println!("ERC7739Context: {}", ERC7739Context::eip712_type_hash(&foo.allowedERC7739Content[0]));




    println!("DataHashes");
    println!("ERC7739Context: {}", ERC7739Context::eip712_hash_struct(&foo.allowedERC7739Content[0]));
    println!("ERC7739Data: {}", ERC7739Data::eip712_hash_struct(&foo));


    println!("SignedSession: {}", SignedSession::eip712_hash_struct(&signed_session));
    println!("Policy: {}", PolicyData::eip712_hash_struct(&session.userOpPolicies[0]));
    println!("ERC7739Data: {}", ERC7739Data::eip712_hash_struct(&session.erc7739Policies));
    println!("Actions: {}", ActionData::eip712_hash_struct(&session.actions[0]));


}

