#![no_std]

use smart_wallet_interface::{types::{Signature, SignerKey}, PolicyInterface};
use soroban_sdk::{
    auth::{Context, ContractContext, CustomAccountInterface}, contract, contractclient, contractimpl, crypto::Hash, panic_with_error, symbol_short, Address, Env, IntoVal, Symbol, TryFromVal, Val, Vec
};
use types::{Error, Signatures, SignerPubKey, SimpleMultiSig};
use smart_wallet_utils::verify::verify_secp256r1_signature;

pub mod types;
pub mod policy_context;
mod test;

#[contract]
pub struct Contract;

const ADMIN: Symbol = symbol_short!("admin");
const POLICY_SIGNERS: Symbol = symbol_short!("p_signers");
const WEEK_OF_LEDGERS: u32 = 60 * 60 * 24 / 5 * 7;

#[contractimpl]
impl PolicyInterface for Contract {
    fn policy__(env: Env, source: Address, signer: SignerKey, contexts: Vec<Context>) {
        if !env.storage().instance().has(&ADMIN) || !env.storage().instance().has(&POLICY_SIGNERS) {
            panic_with_error!(&env, Error::SecurerNotProperlySetUp);
        } 
        // We need to authenticate this policy__ call for this specific source and signer and CONTEXT!!
        // BUT: We want to ensure the context for the policy isn't passed as it would not be possible to deterministically prepare, as the context contains this call.
        let contexts_without_policy_ctx = policy_context::filter_policy_context(&env, &contexts, &env.current_contract_address()); 
        env.current_contract_address().require_auth_for_args((source,signer,contexts_without_policy_ctx).into_val(&env)); 
    }
}

#[contractclient(name = "SecurerAdminClient")]
pub trait SecurerInterface: PolicyInterface {
    fn init_securer(env: Env, admins: SimpleMultiSig, policy_signers: SimpleMultiSig) -> Result<(), Error>;
    fn update_admins(env: Env, admins: SimpleMultiSig) -> Result<(), Error>;
    fn update_securer(env: Env, policy_signers: Address) -> Result<(), Error>;
}

#[contractimpl]
impl SecurerInterface for Contract {
    fn init_securer(env: Env, admins: SimpleMultiSig, policy_signers: SimpleMultiSig) -> Result<(), Error>{
        if env.storage().instance().has(&ADMIN) || env.storage().instance().has(&POLICY_SIGNERS) {
            return Err(Error::SecurerAlreadyExists);
        } 

        check_multisig_construction(&admins)?;
        check_multisig_construction(&policy_signers)?;

        env.storage().instance().set(&ADMIN, &admins);
        env.storage().instance().set(&POLICY_SIGNERS, &policy_signers);

        let max_ttl = env.storage().max_ttl();
        env.storage().instance().extend_ttl(max_ttl - WEEK_OF_LEDGERS, max_ttl);

        Ok(())
    }
    fn update_admins(env: Env, admins: SimpleMultiSig) -> Result<(), Error>{

        if !env.storage().instance().has(&POLICY_SIGNERS) || !env.storage().instance().has(&ADMIN) {
            return Err(Error::SecurerDoesntExists);
        }
        // Admin authentication
        env.current_contract_address().require_auth();

        check_multisig_construction(&admins)?;

        env.storage().instance().set(&ADMIN, &admins);

        let max_ttl = env.storage().max_ttl();
        env.storage().instance().extend_ttl(max_ttl - WEEK_OF_LEDGERS, max_ttl);

        Ok(())
    }
    fn update_securer(env: Env, policy_signers: Address) -> Result<(), Error>{
        if !env.storage().instance().has(&POLICY_SIGNERS) || !env.storage().instance().has(&ADMIN) {
            return Err(Error::SecurerDoesntExists);
        }
        // Admin authentication
        env.current_contract_address().require_auth();

        env.storage().instance().set(&POLICY_SIGNERS, &policy_signers);

        let max_ttl = env.storage().max_ttl();
        env.storage().instance().extend_ttl(max_ttl - WEEK_OF_LEDGERS, max_ttl);

        Ok(())
    }
}


#[contractimpl]
impl CustomAccountInterface for Contract {
    type Error = Error;
    type Signature = Signatures;

    #[allow(non_snake_case)]
    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        signatures: Signatures,
        auth_contexts: Vec<Context>,
    ) -> Result<(), Error> {
        for context in auth_contexts.iter() {
            match context {
                Context::Contract(ContractContext { contract: contract_addr, fn_name, ..}) => {
                   if contract_addr == env.current_contract_address() && fn_name == symbol_short!("policy__") {
                        // Signer authentication
                        let policy_signers = env.storage().instance().get::<Symbol, SimpleMultiSig>(&POLICY_SIGNERS).unwrap();
                        check_simple_multisig(&env, &policy_signers, &signatures, &signature_payload)?;
                   } else {
                        // Admin authentication
                        let admins = env.storage().instance().get::<Symbol, SimpleMultiSig>(&ADMIN).unwrap();
                        check_simple_multisig(&env, &admins, &signatures, &signature_payload)?;
                   }
                }
                Context::CreateContractHostFn(_) => panic_with_error!(&env, Error::NotAllowed),
            }
        }

        Ok(())
    }
}

fn check_simple_multisig(env: &Env, simple_multisig: &SimpleMultiSig, signatures: &Signatures, signature_payload:&Hash<32>) -> Result<(), Error> {
    // // Check the signatures and threshold
    let mut threshold : u8 = 0;
    for signer in simple_multisig.signers.iter(){
        let signature = signatures.0.get(signer.clone()).flatten();
        if let Some(sig) = signature {
            verify_signature(&env, &signer, &sig, &signature_payload);
            threshold += 1;
        }
    }
    if threshold < simple_multisig.threshold.get(0).unwrap() {
        panic_with_error!(env, Error::ThresholdNotMet)
    }

    Ok(())
}


fn verify_signature(env: &Env, signer_key: &SignerPubKey, signature: &Signature, signature_payload: &Hash<32>) -> bool {
    match signature {
            Signature::Ed25519(signature) => {
                if let SignerPubKey::Ed25519(public_key) = &signer_key {
                    env.crypto().ed25519_verify(
                        &public_key,
                        &signature_payload.clone().into(),
                        &signature,
                    );
                    return true;
                }
            }
            Signature::Secp256r1(signature) => {
                if let SignerPubKey::Secp256r1(public_key) = &signer_key {
                    verify_secp256r1_signature(
                        &env,
                        &signature_payload,
                        &public_key,
                        signature.clone(),
                    );
                    return true;
                }
            }
        }
    false
}


fn check_multisig_construction(multisig: &SimpleMultiSig) -> Result<(), Error> {
    // Check no duplicate signers
    let len_signers = multisig.signers.len();
    if len_signers > 255 {
        return Err(Error::TooManySigners);
    }

    if multisig.threshold.get(0).unwrap() > len_signers as u8 {
        return Err(Error::ThresholdGreaterThanSigners);
    }


    if has_duplicates(&multisig.signers){
        return Err(Error::RecoverySignersHasDuplicates);
    }

    Ok(())
}

// ALSO IN RECOVERY
/** This is a very innefficient implementation in O(n^2)
 * A better one would imply having struct implementation Ord for using a sorting algorithm
 * Another one would use a HashSet (which is in std)
 */
fn has_duplicates<T: PartialEq + IntoVal<Env, Val> + TryFromVal<Env, Val>,>(items: &Vec<T>) -> bool {
    let len = items.len();
    for (i,elem) in items.into_iter().enumerate(){
        for elem2 in items.slice((i as u32)+1..len){
            if elem == elem2 {
                return true;
            }
        }
    }
    false // No duplicates
}