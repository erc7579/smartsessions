
use alloy::{
    dyn_abi::SolType,
    primitives::{Address, address, b256, bytes, fixed_bytes, FixedBytes, keccak256, Bytes, U256},
    signers::{local::PrivateKeySigner, Signer},
    sol,
    sol_types::{eip712_domain, SolStruct},
};
use std::vec::Vec;

use eyre::Result;
use hex;
use serde::Serialize; 


sol! {
    #[allow(missing_docs)]
    #[derive(Serialize)]
    struct Session {
        address sessionValidator;
        bytes sessionValidatorInitData;
        bytes32 salt;
        PolicyData[] userOpPolicies;
        ERC7739Data erc7739Policies;
        ActionData[] actions;
        bool permit4337Paymaster;
    }


    #[allow(missing_docs)]
    #[derive(Serialize)]
    struct SignedPermissions {
        bool permitGenericPolicy;
        bool permitAdminAccess;
        bool ignoreSecurityAttestations;
        bool permitERC4337Paymaster;
        PolicyData[] userOpPolicies;
        ERC7739Data erc7739Policies;
        ActionData[] actions;
    }



    #[allow(missing_docs)]
    #[derive(Serialize)]
    struct SignedSession {
        address account;
        SignedPermissions permissions;
        address sessionValidator;
        bytes sessionValidatorInitData;
        bytes32 salt;
        address smartSession;
        uint256 nonce;
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
    struct ERC7739Context {
        bytes32 appDomainSeparator;
        string[] contentName;
    }

    #[allow(missing_docs)]
    #[derive(Serialize)]
    struct ERC7739Data {
        ERC7739Context[] allowedERC7739Content;
        PolicyData[] erc1271Policies;
    }
}


sol!{
    #[allow(missing_docs)]
    #[derive(Serialize)]
    struct ChainSession {
        uint64 chainId;
        Session session;
    }

    #[allow(missing_docs)]
    #[derive(Serialize)]
    struct MultiChainSession {
        ChainSession[] sessionsAndChainIds;
    }

    #[allow(missing_docs)]
    #[derive(Serialize)]
    struct EnableSession {
        uint8 chainDigestIndex;
        ChainDigest[] hashesAndChainIds;
        Session sessionToEnable;
        bytes permissionEnableSig;
    }

    #[allow(missing_docs)]
    #[derive(Serialize)]
    struct ChainDigest {
        uint64 chainId;
        bytes32 sessionDigest;
    }

}


impl From<ChainSession> for ChainDigest {
    fn from(session: ChainSession) -> Self {
        ChainDigest {
            chainId: session.chainId,
            sessionDigest: session.session.eip712_hash_struct(),
        }
    }
}

pub fn to_signed_session(session: Session, account: Address, smart_session: Address, mode: u8, nonce: U256) -> SignedSession {


    let permissions = SignedPermissions{
        permitGenericPolicy: false,
        permitAdminAccess: false,
        ignoreSecurityAttestations: false,
        permitERC4337Paymaster: session.permit4337Paymaster,
        userOpPolicies: session.userOpPolicies,
        erc7739Policies: session.erc7739Policies,
        actions: session.actions,
    };
    SignedSession {
        account,
        permissions,
        sessionValidator: session.sessionValidator,
        sessionValidatorInitData: session.sessionValidatorInitData,
        smartSession: smart_session,
        salt: session.salt,
        nonce
    }
}

