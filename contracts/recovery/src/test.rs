#![cfg(test)]

use std::println;
extern crate std;

use smart_wallet::{Contract as SmartWalletContract, ContractClient as SmartWalletClient};
use ed25519_dalek::{Keypair, Signer as _};
use example_contract::{Contract as ExampleContract, ContractClient as ExampleContractClient};
use sample_policy::Contract as SamplePolicyContract;
use crate::{types::{Condition, ConditionSignatures, Recovery, SignerPubKey}, Contract as RecoveryContract, RecoveryClient};
use smart_wallet_interface::types::{
    Signature, Signatures, Signer, SignerKey, SignerLimits, SignerStorage,
};
use soroban_sdk::{
    auth::{Context, ContractContext}, map, testutils::{EnvTestConfig, Ledger}, token, vec, xdr::{
        HashIdPreimage, HashIdPreimageSorobanAuthorization, InvokeContractArgs, Limits, SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials, ToXdr, VecM, WriteXdr
    }, Address, Bytes, BytesN, Env, IntoVal, String, Symbol,
};
use stellar_strkey::{ed25519, Strkey};


fn sign_payload(env: &Env, nonce: i64, simple_ed25519_keypair : &Keypair, signature_expiration_ledger: u32, root_invocation: &SorobanAuthorizedInvocation) -> Signature {
    let payload = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: env.ledger().network_id().to_array().into(),
        nonce,
        signature_expiration_ledger,
        invocation: root_invocation.clone(),
    });
    let payload = payload.to_xdr(Limits::none()).unwrap();
    let payload = Bytes::from_slice(&env, payload.as_slice());
    let payload = env.crypto().sha256(&payload);

    let simple_ed25519_signature = Signature::Ed25519(BytesN::from_array(
        &env,
        &simple_ed25519_keypair
            .sign(payload.to_array().as_slice())
            .to_bytes(),
    ));

    return simple_ed25519_signature;
}



struct SimpleEd25519 {
    keypair: Keypair,
    address: Address,
    bytes: BytesN<32>,
    signer_key: SignerKey,
}

fn get_simple_ed25519(env: &Env) -> SimpleEd25519 {
    // Simple Ed25519
    let simple_ed25519_keypair = Keypair::from_bytes(&[
        149, 154, 40, 132, 13, 234, 167, 87, 182, 44, 152, 45, 242, 179, 187, 17, 139, 106, 49, 85,
        249, 235, 17, 248, 24, 170, 19, 164, 23, 117, 145, 252, 172, 35, 170, 26, 69, 15, 75, 127,
        192, 170, 166, 54, 68, 127, 218, 29, 130, 173, 159, 1, 253, 192, 48, 242, 80, 12, 55, 152,
        223, 122, 198, 96,
    ])
    .unwrap();

    let simple_ed25519_strkey =
        Strkey::PublicKeyEd25519(ed25519::PublicKey(simple_ed25519_keypair.public.to_bytes()));
    let simple_ed25519_address =
        Bytes::from_slice(&env, simple_ed25519_strkey.to_string().as_bytes());
    let simple_ed25519_address = Address::from_string_bytes(&simple_ed25519_address);

    let simple_ed25519_bytes = simple_ed25519_address.clone().to_xdr(&env);
    let simple_ed25519_bytes = simple_ed25519_bytes.slice(simple_ed25519_bytes.len() - 32..);
    let mut simple_ed25519_array = [0u8; 32];
    simple_ed25519_bytes.copy_into_slice(&mut simple_ed25519_array);
    let simple_ed25519_bytes = BytesN::from_array(&env, &simple_ed25519_array);
    let simple_ed25519_signer_key = SignerKey::Ed25519(simple_ed25519_bytes.clone());
    SimpleEd25519 {
        keypair: simple_ed25519_keypair,
        address: simple_ed25519_address,
        bytes: simple_ed25519_bytes,
        signer_key: simple_ed25519_signer_key,
    }
}


struct Environment<'a> {
    env: Env,
    signature_expiration_ledger: u32,
    wallet_address: Address,
    wallet_client: SmartWalletClient<'a>,
    // example_contract_client: ExampleContractClient<'a>,
    recovery_client: RecoveryClient<'a>,
    // sac_address: Address,
    recovery_policy_address: Address,
    // sample_policy_address: Address,
}


fn set_up<'a>() -> Environment<'a>{
    let mut env: Env = Env::default();

    env.set_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    });

    let signature_expiration_ledger = env.ledger().sequence() + 100;

    let wallet_address = env.register_contract(None, SmartWalletContract);
    let wallet_client = SmartWalletClient::new(&env, &wallet_address);

    let example_contract_address = env.register_contract(None, ExampleContract);
    let _example_contract_client = ExampleContractClient::new(&env, &example_contract_address);

    let recovery_policy_address = env.register_contract(None, RecoveryContract);
    let recovery_client = RecoveryClient::new(&env, &recovery_policy_address);

    let _sample_policy_address = env.register_contract(None, SamplePolicyContract);

    // SAC
    let sac_admin = Address::from_string(&String::from_str(
        &env,
        "GD7777777777777777777777777777777777777777777777777773DB",
    ));
    let sac = env.register_stellar_asset_contract_v2(sac_admin);
    let sac_address = sac.address();
    let sac_admin_client = token::StellarAssetClient::new(&env, &sac_address);

    sac_admin_client
        .mock_all_auths()
        .mint(&wallet_address, &100_000_000);


    return Environment {
        env,
        signature_expiration_ledger,
        wallet_address,
        wallet_client,
        // example_contract_client,
        recovery_client,
        // sac_address,
        recovery_policy_address,
        // sample_policy_address
    };
}

#[test]
fn test_init_recovery() {
    
    let set_up = set_up();
    let env = set_up.env;
    let signature_expiration_ledger = set_up.signature_expiration_ledger;
    let wallet_address = set_up.wallet_address;
    let wallet_client = set_up.wallet_client;
    let recovery_client = set_up.recovery_client;
    let recovery_policy_address = set_up.recovery_policy_address;

    let SimpleEd25519 {keypair: simple_ed25519_keypair, 
                       bytes: simple_ed25519_bytes, 
                       signer_key: simple_ed25519_signer_key, .. } 
                       = get_simple_ed25519(&env);

    wallet_client.mock_all_auths().add_signer(&Signer::Ed25519(
        simple_ed25519_bytes.clone(),
        None,
        SignerLimits(map![&env]),
        SignerStorage::Persistent,
    ));

    // Test adding a recovery
    let recovery = Recovery {
        signers: vec![&env, SignerPubKey::Ed25519(simple_ed25519_bytes.clone())],
        conditions : vec![&env, Condition {
            signers_indexes: Bytes::from_array(&env, &[0]),
            threshold: BytesN::from_array(&env, &[1]),
            inactivity_time: 60 // 60s as an example: you should definitively choose something in the range of days / weeks 
        }],
    };

    let add_recovery_invocation = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: recovery_policy_address.clone().try_into().unwrap(),
            function_name: "init_recovery".try_into().unwrap(),
            args: std::vec![
                wallet_address.clone().try_into().unwrap(),
                recovery.clone().try_into().unwrap(),
            ]
            .try_into()
            .unwrap(),
        }),
        sub_invocations: VecM::default(), // No need to specify __check_auth of the Smart Wallet because 
        // __check_auth don't do any other calls with authentication. 
        // But this will happens when we try to call another function that will call the authentication on our Smart Wallet !
    };
    let nonce = 5;
    let simple_ed25519_signature = sign_payload(&env,nonce, &simple_ed25519_keypair, signature_expiration_ledger, &add_recovery_invocation);

    let init_recovery_auth = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: wallet_address.clone().try_into().unwrap(),
            nonce,
            signature_expiration_ledger,
            signature: Signatures(map![
                &env,
                (
                    simple_ed25519_signer_key.clone(),
                    Some(simple_ed25519_signature)
                ),
            ])
            .try_into()
            .unwrap(),
        }),
        root_invocation: add_recovery_invocation.clone(),
    };

    let current_time = 12345;
    env.ledger().with_mut(|li| {
        li.timestamp = current_time;
    });
    env.budget().reset_default();

    recovery_client.set_auths(&[init_recovery_auth]).init_recovery(
        &wallet_address,
        &recovery
    );

    let time = recovery_client.get_last_active_time();

    assert_eq!(time,12345);

}


#[test] 
fn test_recover_wallet(){

    let set_up = set_up();
    let env = set_up.env;
    let signature_expiration_ledger = set_up.signature_expiration_ledger;
    let wallet_address = set_up.wallet_address;
    let recovery_client = set_up.recovery_client;
    let recovery_policy_address = set_up.recovery_policy_address;
    let wallet_client = set_up.wallet_client;

    let SimpleEd25519 {keypair: simple_ed25519_keypair, 
                       bytes: simple_ed25519_bytes, .. } 
                       = get_simple_ed25519(&env);

    let recovery = Recovery {
        signers: vec![&env, SignerPubKey::Ed25519(simple_ed25519_bytes.clone())],
        conditions : vec![&env, Condition {
            signers_indexes: Bytes::from_array(&env, &[0]),
            threshold: BytesN::from_array(&env, &[1]),
            inactivity_time: 60 // 60s as an example: you should definitively choose something in the range of days / weeks 
        }],
    };

    recovery_client.mock_all_auths().init_recovery(&wallet_address, &recovery);

    let new_signer = Signer::Ed25519(
        simple_ed25519_bytes.clone(),
        None,
        SignerLimits(map![
            &env,
        ]),
        SignerStorage::Persistent,
    );


    let signer_key_recovery_policy = SignerKey::Policy(recovery_policy_address.clone());
    // Add the policy: 
    wallet_client.mock_all_auths().add_signer(&Signer::Policy(
        recovery_policy_address.clone(),
        None,
        SignerLimits(map![&env,]),
        SignerStorage::Persistent,
    ));

    let context_add_signer : Context =  Context::Contract(ContractContext {
        contract: wallet_address.clone(),
        fn_name: Symbol::new(&env, "add_signer"),
        args: (new_signer.clone(),).into_val(&env),
    });

    let policy_invocation = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: recovery_policy_address.clone().try_into().unwrap(),
            function_name: "policy__".try_into().unwrap(),
            args: std::vec![
                wallet_address.clone().try_into().unwrap(),
                signer_key_recovery_policy.clone().try_into().unwrap(),
                std::vec![context_add_signer.clone()].try_into().unwrap(),
            ].try_into().unwrap(),
        }),
        sub_invocations: std::vec![].try_into().unwrap(),
    };


    let add_signer_invocation = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: wallet_address.clone().try_into().unwrap(),
            function_name: "add_signer".try_into().unwrap(),
            args: std::vec![
                new_signer.clone().try_into().unwrap(),
            ]
            .try_into()
            .unwrap(),
        }),
        sub_invocations: std::vec![].try_into().unwrap(), 
    };

    let nonce = 6;
    let simple_ed25519_signature = sign_payload(&env,nonce, &simple_ed25519_keypair, signature_expiration_ledger, &policy_invocation);

    let policy_auth = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: recovery_policy_address.clone().try_into().unwrap(),
            nonce: nonce,
            signature_expiration_ledger,
            signature: (ConditionSignatures {
                condition_index: 0,
                signatures: map![
                    &env,
                    (SignerPubKey::Ed25519(simple_ed25519_bytes.clone()), Some(simple_ed25519_signature))
                ]
            }).try_into()
              .unwrap(),
        }),
        root_invocation: policy_invocation.clone(),
    };

    let wallet_auth = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: wallet_address.clone().try_into().unwrap(),
            nonce: nonce + 1,
            signature_expiration_ledger,
            signature: Signatures(map![
                &env,
                (SignerKey::Policy(recovery_policy_address.clone()), None),
            ])
            .try_into()
            .unwrap(),
        }),
        root_invocation: add_signer_invocation.clone(),
    };


    let time = env.ledger().timestamp();
    env.ledger().with_mut(|li| {
        li.timestamp = time + 2;
    });

 
    let result = wallet_client.set_auths(&[wallet_auth,policy_auth]).try_add_signer(&new_signer);
    println!("{:?}", result.unwrap_err().unwrap());
    // assert_eq!(result, Err(Ok(RecoveryError::InactivityTimeNotMet)));

    let time = env.ledger().timestamp();
    env.ledger().with_mut(|li| {
        li.timestamp = time + 60;
    });

    let nonce_2 = 9;
    let simple_ed25519_signature_2 = sign_payload(&env,nonce_2, &simple_ed25519_keypair, signature_expiration_ledger, &policy_invocation);

    let policy_auth = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: recovery_policy_address.clone().try_into().unwrap(),
            nonce: nonce_2,
            signature_expiration_ledger,
            signature: (ConditionSignatures {
                condition_index: 0,
                signatures: map![
                    &env,
                    (SignerPubKey::Ed25519(simple_ed25519_bytes.clone()), Some(simple_ed25519_signature_2))
                ]
            }).try_into()
              .unwrap(),
        }),
        root_invocation: policy_invocation.clone(),
    };

    let wallet_auth = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: wallet_address.clone().try_into().unwrap(),
            nonce: nonce_2 + 1 ,
            signature_expiration_ledger,
            signature: Signatures(map![
                &env,
                (SignerKey::Policy(recovery_policy_address.clone()), None),
            ])
            .try_into()
            .unwrap(),
        }),
        root_invocation: add_signer_invocation.clone(),
    };



    wallet_client.set_auths(&[wallet_auth,policy_auth]).add_signer(&new_signer);



    println!("{:?}", env.budget().print());
}