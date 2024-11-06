#![no_std]

use smart_wallet_interface::{types::{Signature, SignerKey}, PolicyInterface};
use soroban_sdk::{
    auth::{Context, ContractContext, CustomAccountInterface}, contract, contractclient, contractimpl, crypto::Hash, panic_with_error, symbol_short, Address, Bytes, Env, IntoVal, Symbol, TryFromVal, Val, Vec
};
use types::{ConditionSignatures, Error, Recovery, SignerPubKey};
use smart_wallet_utils::verify::verify_secp256r1_signature;

pub mod types;
mod test;

#[contract]
pub struct Contract;

const SMART_WALLET: Symbol = symbol_short!("wallet");
const RECOVERY: Symbol = symbol_short!("recovery");
const WEEK_OF_LEDGERS: u32 = 60 * 60 * 24 / 5 * 7;
const LAST_ACTIVE_TIMESTAMP: Symbol = symbol_short!("last_tx"); 
// This should be updated regularly: It could/should actually be embedded in the smart wallet and updated on each 
// auth transaction (because it makes it "almost free update") but it add more complexity to the smart wallet implementation and add an "options" struct.
// So it will stay as a contract storage for now but any wallet implementation should update it regularly.
// last_active_time is used for inactivity-time based recovery. A view function can access it.

#[contractimpl]
impl PolicyInterface for Contract {
    fn policy__(env: Env, source: Address, _signer: SignerKey, contexts: Vec<Context>) {
        let mut context_found = false;
        let wallet_address = env.storage().instance().get::<Symbol, Address>(&SMART_WALLET).unwrap();
        for context in contexts.iter() {
            match context {
                Context::Contract(ContractContext { contract: contract_addr, fn_name, .. }) => {
                    // We only use this policy for adding signer to the smart wallet
                    if contract_addr == source && contract_addr == wallet_address && fn_name == Symbol::new(&env, "add_signer"){
                        context_found = true;

                        if !env.storage().instance().has(&RECOVERY) {
                            panic_with_error!(&env,Error::RecoveryDoesNotExist);
                        }
                        // Require signers signature and time check: __check_auth 
                        env.current_contract_address().require_auth();
                    }        
                }

                _ => {},
            }
        }

        if !context_found {
            panic_with_error!(&env, Error::PolicyOnlyAllowToAddSignerToSW);
        } 
    }
}


#[contractclient(name = "RecoveryClient")]
pub trait RecoveryInterface: PolicyInterface {
    fn init_recovery(env: Env, smart_wallet_addr: Address, recovery: Recovery) -> Result<(), Error>;
    fn update_recovery(env: Env, smart_wallet_addr: Address, recovery: Recovery) -> Result<(), Error>;
    fn update_last_active_time(env: Env, smart_wallet_addr: Address) -> Result<(), Error>;
    fn get_last_active_time(env: Env) -> Result<u64, Error>;
}

#[contractimpl]
impl RecoveryInterface for Contract {
    fn init_recovery(env: Env, smart_wallet_addr: Address, recovery: Recovery) -> Result<(), Error>{
        if env.storage().instance().has(&SMART_WALLET) || env.storage().instance().has(&RECOVERY) {
            return Err(Error::RecoveryAlreadyExists);
        } 
        smart_wallet_addr.require_auth();
        env.storage().instance().set(&SMART_WALLET, &smart_wallet_addr);

        check_recovery_construction(&recovery)?;

        if env.storage().instance().has(&RECOVERY) {
            return Err(Error::RecoveryAlreadyExists);
        }

        // Init the last_tx_timestamp
        env.storage().instance().set(&LAST_ACTIVE_TIMESTAMP, &env.ledger().timestamp());

        // Store the recovery
        env.storage().instance().set(&RECOVERY, &recovery);

        let max_ttl = env.storage().max_ttl();
        env.storage().instance().extend_ttl(max_ttl - WEEK_OF_LEDGERS, max_ttl);


        Ok(())
    }
    fn update_recovery(env: Env, smart_wallet_addr: Address, recovery: Recovery) -> Result<(), Error>{

        if smart_wallet_addr != env.storage().instance().get::<Symbol, Address>(&SMART_WALLET).unwrap() {
            return Err(Error::SmartWalletNotMatching);
        }
 
        smart_wallet_addr.require_auth(); // Need auth from the smart wallet

        check_recovery_construction(&recovery)?;

        if !env.storage().instance().has(&RECOVERY) {
            return Err(Error::RecoveryDoesNotExist);
        }

        env.storage().instance().set(&RECOVERY, &recovery);

        let max_ttl = env.storage().max_ttl();
        env.storage().instance().extend_ttl(max_ttl - WEEK_OF_LEDGERS, max_ttl);

        Ok(())

    }
    fn update_last_active_time(env: Env, smart_wallet_addr: Address) -> Result<(), Error>{

        if smart_wallet_addr != env.storage().instance().get::<Symbol, Address>(&SMART_WALLET).unwrap() {
            return Err(Error::SmartWalletNotMatching);
        }

        smart_wallet_addr.require_auth(); // This is actually the costly part of the transaction 

        env.storage().instance().set(&LAST_ACTIVE_TIMESTAMP, &env.ledger().timestamp());

        Ok(())
    }
    fn get_last_active_time(env: Env) -> Result<u64, Error> {
        Ok(env.storage().instance().get::<Symbol, u64>(&LAST_ACTIVE_TIMESTAMP).unwrap())
    }
}


#[contractimpl]
impl CustomAccountInterface for Contract {
    type Error = Error;
    type Signature = ConditionSignatures;

    #[allow(non_snake_case)]
    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        signatures: ConditionSignatures,
        _auth_contexts: Vec<Context>,
    ) -> Result<(), Error> {

        let recovery = env.storage().instance().get::<Symbol, Recovery>(&RECOVERY).unwrap();

        let (list_signers, condition) = recovery.get_list_signers_and_condition(&env, signatures.condition_index).unwrap(); 
        
        // Check if the inactivity time is met        
        let last_tx_timestamp = env.storage().instance().get::<Symbol, u64>(&LAST_ACTIVE_TIMESTAMP).unwrap();
        let current_timestamp = env.ledger().timestamp();
        if current_timestamp.checked_sub(last_tx_timestamp).unwrap() > condition.inactivity_time {
            panic_with_error!(env, Error::InactivityTimeNotMet)
        }

        // Check the signatures and threshold
        if list_signers.len() > 255 { // This shouldn't be useful because we already checked it in the recovery construction
            panic_with_error!(env, Error::TooManySigners)
        }
        let mut threshold : u8 = 0;
        for signer in list_signers.iter(){
            let signature = signatures.signatures.get(signer.clone()).flatten();
            if let Some(sig) = signature {
                verify_signature(&env, &signer, &sig, &signature_payload);
                threshold += 1;
            }
        }

        if threshold < condition.threshold.get(0).unwrap() {
            panic_with_error!(env, Error::ThresholdNotMet)
        }

        Ok(())
        }
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



fn check_recovery_construction(recovery : &Recovery) -> Result<(),Error>{

    // Check no duplicate signers
    let len_signers = recovery.signers.len();
    if len_signers > 255 {
        return Err(Error::TooManySigners);
    }

    if has_duplicates(&recovery.signers){
        return Err(Error::RecoverySignersHasDuplicates);
    }

    // Check conditions doesn't have duplicates signers &&
    // Check conditions doesn't go over the signers length
    for condition in &recovery.conditions{
        if has_duplicates_bytes(&condition.signers_indexes){
            return Err(Error::RecoveryConditionHasDuplicateSigners);
        }
        if condition.signers_indexes.iter().any(|val| val >= len_signers as u8){
            return Err(Error::RecoveryMalformedCondition);
        }
    }


    Ok(())
}

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
/** TODO: make it DRY */
fn has_duplicates_bytes(items: &Bytes) -> bool {
    let len = items.len();
    for (i,elem) in items.iter().enumerate(){
        for elem2 in items.slice((i as u32)+1..len){
            if elem == elem2 {
                return true;
            }
        }
    }
    false // No duplicates
}