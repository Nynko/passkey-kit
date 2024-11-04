#![no_std]

use soroban_sdk::{auth::Context, contractclient, Address, BytesN, Env, Vec};
use types::{Condition, Error, Recovery, Signer, SignerKey};

pub mod types;

#[contractclient(name = "WebAuthnClient")]
pub trait WebAuthnInterface {
    fn add(env: Env, signer: Signer) -> Result<(), Error>;
    fn remove(env: Env, signer_key: SignerKey) -> Result<(), Error>;
    fn update(env: Env, hash: BytesN<32>) -> Result<(), Error>;
}

/**
 * Interface for implementing recovery functionality to a wallet implementing WebAuthnInterface
 * It allows to specify a list of signers and a list of conditions : Conditions specify signers from the list of signers, threshold signatures and inactivity time in seconds 
 * A last_tx_timestamp is stored in the contract storage to keep track of the last transaction time
 * Recovering the account means redefining the list of signers in the WebAuthnInterface
 */
#[contractclient(name = "RecoveryClient")]
pub trait RecoveryInterface: WebAuthnInterface {
    fn add_recovery(env: Env, recovery: Recovery) -> Result<(), Error>;
    fn update_recovery(env: Env, recovery: Recovery) -> Result<(), Error>;
    fn recover(env:Env, condition_index: u32, new_signer: Signer) -> Result<(), Error>;
}

#[contractclient(name = "PolicyClient")]
pub trait PolicyInterface {
    fn policy__(env: Env, source: Address, contexts: Vec<Context>);
}
