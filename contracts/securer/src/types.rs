use smart_wallet_interface::types::Signature;
use soroban_sdk::{contracterror, contracttype, Address, BytesN, Map, Vec};


#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum Error {
    SecurerNotProperlySetUp = 1,
    ThresholdNotMet = 2,
    NotAllowed = 3,
    SecurerAlreadyExists = 4,
    TooManySigners = 5,
    ThresholdGreaterThanSigners = 6,
    RecoverySignersHasDuplicates = 7,
    SecurerDoesntExists = 8,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum SignerPubKey {
    Policy(Address),
    Ed25519(BytesN<32>),
    Secp256r1(BytesN<65>),
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Signatures(pub Map<SignerPubKey, Option<Signature>>);

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct SimpleMultiSig {
    pub signers: Vec<SignerPubKey>, // Maximum 255 signers 
    pub threshold: BytesN<1>,
}
