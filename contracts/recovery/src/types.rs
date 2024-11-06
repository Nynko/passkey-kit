use smart_wallet_interface::types::Signature;
use soroban_sdk::{contracterror, contracttype, Address, Bytes, BytesN, Env, Map, Vec};


#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum Error {
    RecoveryDoesNotExist= 1,
    RecoveryAlreadyExists = 2,
    InactivityTimeNotMet = 3,
    PolicyOnlyAllowToAddSignerToSW = 4,
    SmartWalletNotMatching = 5,
    ActionNotAuthorized = 6,
    NotAllowed = 7,
    TooManySigners = 8,
    RecoverySignersHasDuplicates = 9,
    RecoveryConditionHasDuplicateSigners = 10,
    RecoveryMalformedCondition = 11,
    ConditionIndexOutOfBounds = 12,
    ThresholdNotMet = 13,
}


#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum SignerPubKey {
    Policy(Address),
    Ed25519(BytesN<32>),
    Secp256r1(Bytes, BytesN<65>),
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct ConditionSignatures{
    pub condition_index: u32,
    pub signatures: Map<SignerPubKey, Option<Signature>>
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Recovery{
    pub signers: Vec<SignerPubKey>, // Maximum 255 signers because it doesn't make sense to have more
    pub conditions: Vec<Condition>
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Condition {
    pub signers_indexes: Bytes, // Each byte is the index of the signer + Assuming if this is empty we use all the signers
    pub threshold: BytesN<1>, 
    pub inactivity_time: u64
}

impl Recovery {
    // This should be potentially improve for better performance
    // But recovery doesn't happen often, so it's fine for now
    // We optimized for storage here by using Bytes...
    pub fn get_list_signers_and_condition(&self, env: &Env, condition_index: u32) -> Result<(Vec<SignerPubKey>, Condition),Error> {
        let mut signers = Vec::new(&env);
        let condition = self.conditions.get(condition_index);
        match condition {
            None => {
                return Err(Error::ConditionIndexOutOfBounds);
            }
            Some(condition) => {
                let signers_indexes = &condition.signers_indexes;
                if signers_indexes.len() == 0 {
                    return Ok((self.signers.clone(),condition)); // Return all signers if signers_indexes is empty
                }
                for index in signers_indexes.iter() {
                    let signer = self.signers.get(index.into());
                    match signer {
                        Some(signer) => {
                            signers.push_back(signer.clone());
                        }
                        None => {
                            return Err(Error::RecoveryMalformedCondition);
                        }
                    }
                }
                return Ok((signers,condition));
            }
        }
    }
}