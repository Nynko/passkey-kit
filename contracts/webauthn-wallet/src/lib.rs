#![no_std]

use soroban_sdk::{
    auth::{Context, ContractContext, CustomAccountInterface}, contract, contractimpl, crypto::Hash, panic_with_error, symbol_short, vec, BytesN, Env, FromVal, IntoVal, Symbol, TryFromVal, Val, Vec, Bytes
};

use webauthn_wallet_interface::{
    types::{
        Error, Recovery, Secp256r1Signature, Signature, Signatures, Signer, SignerKey, SignerLimits, SignerStorage, SignerVal
    }, PolicyClient, RecoveryInterface, WebAuthnInterface
};

mod base64_url;
mod types;

mod test;
mod test_extra;

#[contract]
pub struct Contract;

const WEEK_OF_LEDGERS: u32 = 60 * 60 * 24 / 5 * 7;
const EVENT_TAG: Symbol = symbol_short!("sw_v1");
const SIGNER_COUNT: Symbol = symbol_short!("signers");
const LAST_TX_TIMESTAMP: Symbol = symbol_short!("last_tx"); // This is updated on each require_auth call and use for Recovery
const RECOVERY: Symbol = symbol_short!("recovery");

#[contractimpl]
impl WebAuthnInterface for Contract {
    fn add(env: Env, signer: Signer) -> Result<(), Error> {
        if env.storage().instance().has(&SIGNER_COUNT) {
            env.current_contract_address().require_auth();
        }

        let max_ttl = env.storage().max_ttl();

        let (signer_key, signer_val, signer_storage) = match signer {
            Signer::Policy(policy, signer_limits, signer_storage) => (
                SignerKey::Policy(policy),
                SignerVal::Policy(signer_limits),
                signer_storage,
            ),
            Signer::Ed25519(public_key, signer_limits, signer_storage) => (
                SignerKey::Ed25519(public_key),
                SignerVal::Ed25519(signer_limits),
                signer_storage,
            ),
            Signer::Secp256r1(id, public_key, signer_limits, signer_storage) => (
                SignerKey::Secp256r1(id),
                SignerVal::Secp256r1(public_key, signer_limits),
                signer_storage,
            ),
        };

        store_signer(&env, &signer_key, &signer_val, &signer_storage);

        env.storage()
            .instance()
            .extend_ttl(max_ttl - WEEK_OF_LEDGERS, max_ttl);

        env.events().publish(
            (EVENT_TAG, symbol_short!("add"), signer_key),
            (signer_val, signer_storage),
        );

        Ok(())
    }
    fn remove(env: Env, signer_key: SignerKey) -> Result<(), Error> {
        env.current_contract_address().require_auth();

        if let Some((_, signer_storage)) = get_signer_val_storage(&env, &signer_key, false) {
            // TODO: maybe ensure there is always one signers for security 
            // (if you want to change you need to add then remove the old one)
            update_signer_count(&env, false); 

            match signer_storage {
                SignerStorage::Persistent => {
                    env.storage().persistent().remove::<SignerKey>(&signer_key);
                }
                SignerStorage::Temporary => {
                    env.storage().temporary().remove::<SignerKey>(&signer_key);
                }
            }
        }

        let max_ttl = env.storage().max_ttl();

        env.storage()
            .instance()
            .extend_ttl(max_ttl - WEEK_OF_LEDGERS, max_ttl);

        env.events()
            .publish((EVENT_TAG, symbol_short!("remove"), signer_key), ());

        Ok(())
    }
    fn update(env: Env, hash: BytesN<32>) -> Result<(), Error> {
        env.current_contract_address().require_auth();

        env.deployer().update_current_contract_wasm(hash);

        let max_ttl = env.storage().max_ttl();

        env.storage()
            .instance()
            .extend_ttl(max_ttl - WEEK_OF_LEDGERS, max_ttl);

        Ok(())
    }
}


#[contractimpl]
impl RecoveryInterface for Contract where Contract: WebAuthnInterface {
    fn add_recovery(env: Env, recovery: Recovery) -> Result<(), Error>{
        if !env.storage().instance().has(&SIGNER_COUNT) {
            // You have to set up the smart wallet with a signer before you can set up recovery
            return Err(Error::SmartWalletNotInitialized);
        } 

        check_recovery_construction(&recovery)?;

        env.current_contract_address().require_auth();

        if env.storage().instance().has(&RECOVERY) {
            return Err(Error::RecoveryAlreadyExists);
        }

        // Init the last_tx_timestamp
        env.storage().instance().set(&LAST_TX_TIMESTAMP, &env.ledger().timestamp());

        // Store the recovery
        env.storage().instance().set(&RECOVERY, &recovery);

        let max_ttl = env.storage().max_ttl();
        env.storage().instance().extend_ttl(max_ttl - WEEK_OF_LEDGERS, max_ttl);


        Ok(())
    }
    fn update_recovery(env: Env, recovery: Recovery) -> Result<(), Error>{

        check_recovery_construction(&recovery)?;

        env.current_contract_address().require_auth();

        if !env.storage().instance().has(&RECOVERY) {
            return Err(Error::RecoveryDoesNotExist);
        }

        env.storage().instance().set(&RECOVERY, &recovery);

        let max_ttl = env.storage().max_ttl();
        env.storage().instance().extend_ttl(max_ttl - WEEK_OF_LEDGERS, max_ttl);

        Ok(())

    }
    fn recover(env:Env, condition_index: u32, new_signer: Signer) -> Result<(), Error>{

        if !env.storage().instance().has(&RECOVERY) {
            return Err(Error::RecoveryDoesNotExist);
        }

        let last_tx_timestamp = env.storage().instance().get::<Symbol, u64>(&LAST_TX_TIMESTAMP).unwrap();
        let current_timestamp = env.ledger().timestamp();

        // Check if the inactivity time is met
        let recovery: Recovery = env.storage().instance().get::<Symbol, Recovery>(&RECOVERY).unwrap();
        let condition = recovery.conditions.get(condition_index as u32).unwrap();
        if current_timestamp.checked_sub(last_tx_timestamp).unwrap() > condition.inactivity_time {
            panic_with_error!(env, Error::InactivityTimeNotMet)
        }

        // Require signer signature: __check_auth handle the special case of recovery
        // This is done after inactivity time is checked because time is updated in __check_auth
        env.current_contract_address().require_auth();

        Ok(())

    } 
}

fn store_signer(
    env: &Env,
    signer_key: &SignerKey,
    signer_val: &SignerVal,
    signer_storage: &SignerStorage,
) {
    let max_ttl = env.storage().max_ttl();

    // Include this before the `.set` calls so it doesn't read them as previous values
    let previous_signer_val_and_storage: Option<(SignerVal, SignerStorage)> =
        get_signer_val_storage(env, signer_key, false);

    // Add and extend the signer key in the appropriate storage
    let is_persistent = match signer_storage {
        SignerStorage::Persistent => {
            env.storage()
                .persistent()
                .set::<SignerKey, SignerVal>(signer_key, signer_val);
            env.storage().persistent().extend_ttl::<SignerKey>(
                signer_key,
                max_ttl - WEEK_OF_LEDGERS,
                max_ttl,
            );

            true
        }
        SignerStorage::Temporary => {
            env.storage()
                .temporary()
                .set::<SignerKey, SignerVal>(signer_key, signer_val);
            env.storage().temporary().extend_ttl::<SignerKey>(
                signer_key,
                max_ttl - WEEK_OF_LEDGERS,
                max_ttl,
            );

            false
        }
    };

    if let Some((_, previous_signer_storage)) = previous_signer_val_and_storage {
        // Remove signer key in the opposing storage if it exists
        match previous_signer_storage {
            SignerStorage::Persistent => {
                if !is_persistent {
                    env.storage().persistent().remove::<SignerKey>(signer_key);
                }
            }
            SignerStorage::Temporary => {
                if is_persistent {
                    env.storage().temporary().remove::<SignerKey>(signer_key);
                }
            }
        }
    } else {
        // only need to update the signer count here if we're actually adding vs replacing a signer
        update_signer_count(&env, true);
    }
}

fn update_signer_count(env: &Env, add: bool) {
    let count = env
        .storage()
        .instance()
        .get::<Symbol, i32>(&SIGNER_COUNT)
        .unwrap_or(0)
        + if add { 1 } else { -1 };

    env.storage()
        .instance()
        .set::<Symbol, i32>(&SIGNER_COUNT, &count);
}

#[derive(serde::Deserialize)]
struct ClientDataJson<'a> {
    challenge: &'a str,
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

        // Check if this is a recovery
        if env.storage().instance().has(&RECOVERY) {
            // Update the last_tx for any authenticated transaction
            env.storage().instance().set(&LAST_TX_TIMESTAMP, &env.ledger().timestamp());

            for context in auth_contexts.iter() {
                match context {
                    Context::Contract(contract_context) => {
                        if contract_context.contract == env.current_contract_address() && 
                            contract_context.fn_name == symbol_short!("recover") {
                            
                            let condition_index = contract_context.args.get(2).unwrap();
                            let recovery: Recovery = env.storage().instance().get::<Symbol, Recovery>(&RECOVERY).unwrap();
                            let condition = recovery.conditions.get(condition_index.get_payload() as u32).unwrap();
                            let mut threshold : u8 = 0;
                            for signer_index in condition.allowed_signers_index.iter() {
                                let signer = recovery.signers.get(signer_index as u32).unwrap();
                                let signature = signatures.0.get(signer).flatten();
                                if let Some(sig) = signature {
                                    // verify 
                                    threshold += 1;
                                }

                            }
                            for (signer_key, signature) in signatures.0.iter(){

                            }
                            

                        } else {
                            continue
                        }
                    },
                    _ => continue,
                }
            }
        }

        // Check all contexts for an authorizing signature
        for context in auth_contexts.iter() {
            'check: loop {
                for (signer_key, _signature) in signatures.0.iter() {
                    if let Some((signer_val, _)) = get_signer_val_storage(&env, &signer_key, false)
                    {
                        let signer_limits = match signer_val {
                            SignerVal::Policy(signer_limits) => signer_limits,
                            SignerVal::Ed25519(signer_limits) => signer_limits,
                            SignerVal::Secp256r1(_public_key, signer_limits) => signer_limits,
                        };

                        if verify_context(&env, &context, &signer_key, &signer_limits, &signatures)
                        {
                            break 'check;
                        } else {
                            continue;
                        }
                    }
                }

                panic_with_error!(env, Error::MissingContext);
            }
        }

        // Check all signatures for a matching context
        for (signer_key, signature) in signatures.0.iter() {
            match get_signer_val_storage(&env, &signer_key, true) {
                None => panic_with_error!(env, Error::NotFound), 
                Some((signer_val, _)) => {
                    match signature {
                        None => {
                            // If there's a policy signer in the signatures map we call it as a full forward of this __check_auth's arguments
                            if let SignerKey::Policy(policy) = &signer_key {
                                PolicyClient::new(&env, policy)
                                    .policy__(&env.current_contract_address(), &auth_contexts);
                                continue;
                            }

                            panic_with_error!(&env, Error::SignatureKeyValueMismatch)
                        }
                        Some(signature) => match signature {
                            Signature::Ed25519(signature) => {
                                if let SignerKey::Ed25519(public_key) = &signer_key {
                                    env.crypto().ed25519_verify(
                                        &public_key,
                                        &signature_payload.clone().into(),
                                        &signature,
                                    );
                                    continue;
                                }

                                panic_with_error!(&env, Error::SignatureKeyValueMismatch)
                            }
                            Signature::Secp256r1(signature) => {
                                if let SignerVal::Secp256r1(public_key, _signer_limits) = signer_val
                                {
                                    verify_secp256r1_signature(
                                        &env,
                                        &signature_payload,
                                        &public_key,
                                        signature,
                                    );
                                    continue;
                                }

                                panic_with_error!(&env, Error::SignatureKeyValueMismatch)
                            }
                        },
                    }
                }
            };
        }

        let max_ttl = env.storage().max_ttl();

        env.storage()
            .instance()
            .extend_ttl(max_ttl - WEEK_OF_LEDGERS, max_ttl);

        Ok(())
    }
}

fn verify_context(
    env: &Env,
    context: &Context,
    signer_key: &SignerKey,
    signer_limits: &SignerLimits,
    signatures: &Signatures,
) -> bool {
    if signer_limits.0.is_empty() {
        return true;
    }

    match context {
        Context::Contract(ContractContext {
            contract,
            fn_name,
            args,
        }) => {
            match signer_limits.0.get(contract.clone()) {
                None => false, // signer limitations not met
                Some(signer_limits_keys) => {
                    // If this signer has a smart wallet context limit, limit that context to only removing itself
                    if *contract == env.current_contract_address()
                        && *fn_name != symbol_short!("remove")
                        || (*fn_name == symbol_short!("remove")
                            && SignerKey::from_val(env, &args.get_unchecked(0)) != *signer_key)
                    {
                        return false; // self trying to do something other than remove itself
                    }

                    verify_signer_limit_keys(env, signatures, &signer_limits_keys, &context);

                    true
                }
            }
        }
        Context::CreateContractHostFn(_) => {
            match signer_limits.0.get(env.current_contract_address()) {
                None => false, // signer limitations not met
                Some(signer_limits_keys) => {
                    verify_signer_limit_keys(env, signatures, &signer_limits_keys, &context);

                    true
                }
            }
        }
    }
}

fn verify_signer_limit_keys(
    env: &Env,
    signatures: &Signatures,
    signer_limits_keys: &Option<Vec<SignerKey>>,
    context: &Context,
) {
    if let Some(signer_limits_keys) = signer_limits_keys {
        for signer_limits_key in signer_limits_keys.iter() {
            // Policies SignerLimits don't need to exist in the signatures map, or be stored on the smart wallet for that matter, they can be adjacent as long as they pass their own require_auth_for_args check
            if let SignerKey::Policy(policy) = &signer_limits_key {
                // In the case of a policy signer in the SignerLimits map we need to verify it if that key has been saved to the smart wallet
                // NOTE watch out for infinity loops. If a policy calls itself this will indefinitely recurse
                if let Some((signer_limits_val, _)) =
                    get_signer_val_storage(env, &signer_limits_key, true)
                {
                    if let SignerVal::Policy(signer_limits) = signer_limits_val {
                        if !verify_context(
                            env,
                            context,
                            &signer_limits_key,
                            &signer_limits,
                            signatures,
                        ) {
                            panic_with_error!(env, Error::FailedPolicySignerLimits)
                        }
                    }
                }

                PolicyClient::new(&env, policy)
                    .policy__(&env.current_contract_address(), &vec![env, context.clone()]);
                // For every other SignerLimits key, it must exist in the signatures map and thus exist as a signer on the smart wallet
            } else if !signatures.0.contains_key(signer_limits_key.clone()) {
                // if any required key is missing this contract invocation is invalid
                panic_with_error!(env, Error::MissingSignerLimits)
            }
        }
    }
}

fn get_signer_val_storage(
    env: &Env,
    signer_key: &SignerKey,
    extend_ttl: bool,
) -> Option<(SignerVal, SignerStorage)> {
    let max_ttl = env.storage().max_ttl();

    match env
        .storage()
        .temporary()
        .get::<SignerKey, SignerVal>(signer_key)
    {
        Some(signer_val) => {
            if extend_ttl {
                env.storage().temporary().extend_ttl::<SignerKey>(
                    signer_key,
                    max_ttl - WEEK_OF_LEDGERS,
                    max_ttl,
                );
            }

            Some((signer_val, SignerStorage::Temporary))
        }
        None => {
            match env
                .storage()
                .persistent()
                .get::<SignerKey, SignerVal>(signer_key)
            {
                Some(signer_val) => {
                    if extend_ttl {
                        env.storage().persistent().extend_ttl::<SignerKey>(
                            signer_key,
                            max_ttl - WEEK_OF_LEDGERS,
                            max_ttl,
                        );
                    }

                    Some((signer_val, SignerStorage::Persistent))
                }
                None => None,
            }
        }
    }
}

fn verify_secp256r1_signature(
    env: &Env,
    signature_payload: &Hash<32>,
    public_key: &BytesN<65>,
    signature: Secp256r1Signature,
) {
    let Secp256r1Signature {
        mut authenticator_data,
        client_data_json,
        signature,
    } = signature;

    authenticator_data.extend_from_array(&env.crypto().sha256(&client_data_json).to_array());

    env.crypto().secp256r1_verify(
        &public_key,
        &env.crypto().sha256(&authenticator_data),
        &signature,
    );

    // Parse the client data JSON, extracting the base64 url encoded challenge.
    let client_data_json = client_data_json.to_buffer::<1024>(); // <- TODO why 1024?
    let client_data_json = client_data_json.as_slice();
    let (client_data_json, _): (ClientDataJson, _) =
        serde_json_core::de::from_slice(client_data_json)
            .unwrap_or_else(|_| panic_with_error!(env, Error::JsonParseError));

    // Build what the base64 url challenge is expecting.
    let mut expected_challenge = [0u8; 43];

    base64_url::encode(&mut expected_challenge, &signature_payload.to_array());

    // Check that the challenge inside the client data JSON that was signed is identical to the expected challenge.
    // TODO is this check actually necessary or is the secp256r1_verify sufficient?
    if client_data_json.challenge.as_bytes() != expected_challenge {
        panic_with_error!(env, Error::ClientDataJsonChallengeIncorrect)
    }
}


fn verify_signatures(env: &Env, signature: &Signature, signature_payload: &Hash<32>, signer_key: &SignerKey) -> Result<(), Error>{
    match signature {
        Signature::Ed25519(signature) => {
            if let SignerKey::Ed25519(public_key) = signer_key {
                env.crypto().ed25519_verify(
                    &public_key,
                    &signature_payload.clone().into(),
                    &signature,
                );
                return Ok(());
            }

            return Err(Error::SignatureKeyValueMismatch)
        }
        Signature::Secp256r1(signature) => {
            if let SignerVal::Secp256r1(public_key, _signer_limits) = signer_val
            {
                verify_secp256r1_signature(
                    &env,
                    signature_payload,
                    &public_key,
                    signature.clone(),
                );
                return Ok(());
            }

            return Err(Error::SignatureKeyValueMismatch)
        }
    },
}

fn check_recovery_construction(recovery : &Recovery) -> Result<(),Error>{

    // Check no duplicate signers
    let len_signers = recovery.signers.len();
    if len_signers > 255 {
        return Err(Error::RecoveryTooManySigners);
    }

    if has_duplicates(&recovery.signers){
        return Err(Error::RecoverySignersHasDuplicates);
    }

    // Check conditions doesn't have duplicates signers &&
    // Check conditions doesn't go over the signers length
    for condition in &recovery.conditions{
        if has_duplicates_bytes(&condition.allowed_signers_index){
            return Err(Error::RecoveryConditionHasDuplicateSigners);
        }
        if condition.allowed_signers_index.iter().any(|val| val >= len_signers as u8){
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
        for elem2 in items.slice((i as u32)..len){
            if elem == elem2 {
                return true;
            }
        }
    }
    false // No duplicates
}
/** To make it DRY */
fn has_duplicates_bytes(items: &Bytes) -> bool {
    let len = items.len();
    for (i,elem) in items.iter().enumerate(){
        for elem2 in items.slice((i as u32)..len){
            if elem == elem2 {
                return true;
            }
        }
    }
    false // No duplicates
}