use soroban_sdk::{contracterror, contracttype, Address, Bytes, BytesN, Map, Vec};

#[contracterror(export = false)]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum Error {
    NotFound = 1,
    MissingContext = 2,
    MissingSignerLimits = 3,
    FailedPolicySignerLimits = 4,
    SignatureKeyValueMismatch = 5,
    ClientDataJsonChallengeIncorrect = 6,
    JsonParseError = 7,
    // RECOVERY ERRORS
    SmartWalletNotInitialized = 8,
    RecoveryAlreadyExists = 9,
    RecoveryDoesNotExist = 10,
    RecoveryConditionHasDuplicateSigners = 11,
    RecoverySignersHasDuplicates = 12,
    RecoveryMalformedCondition = 13,
    RecoveryTooManySigners = 14,
    InactivityTimeNotMet = 15,
}


#[contracttype(export = false)]
#[derive(Clone, Debug, PartialEq)]
// Map of contexts this signer can authorize if present in the __check_auth auth_contexts list
// Map value is a list of SignerKeys which must all be present in the __check_auth signatures list in order for the signer to authorize the context
// e.g. a policy runs on a SAC token to check how much it's withdrawing and also requires a signature from an additional ed25519 signer
// e.g. an ed25519 signer can only be used to authorize a specific contract's invocations and no further keys are required
pub struct SignerLimits(pub Map<Address, Option<Vec<SignerKey>>>);

#[contracttype(export = false)]
#[derive(Clone, Debug, PartialEq)]
pub enum SignerKey {
    Policy(Address),
    Ed25519(BytesN<32>),
    Secp256r1(Bytes),
}

#[contracttype(export = false)]
#[derive(Clone, Debug, PartialEq)]
pub enum SignerVal {
    Policy(SignerLimits),
    Ed25519(SignerLimits),
    Secp256r1(BytesN<65>, SignerLimits),
}

#[contracttype(export = false)]
#[derive(Clone, Debug, PartialEq)]
pub enum SignerStorage {
    Persistent,
    Temporary,
}

#[contracttype(export = false)]
#[derive(Clone, Debug, PartialEq)]
pub enum Signer {
    Policy(Address, SignerLimits, SignerStorage),
    Ed25519(BytesN<32>, SignerLimits, SignerStorage),
    Secp256r1(Bytes, BytesN<65>, SignerLimits, SignerStorage),
}

#[contracttype(export = false)]
#[derive(Clone, Debug, PartialEq)]
pub struct Secp256r1Signature {
    pub authenticator_data: Bytes,
    pub client_data_json: Bytes,
    pub signature: BytesN<64>,
}

#[contracttype(export = false)]
#[derive(Clone, Debug, PartialEq)]
pub enum Signature {
    Ed25519(BytesN<64>),
    Secp256r1(Secp256r1Signature),
}

#[contracttype(export = false)]
#[derive(Clone, Debug, PartialEq)]
pub struct Signatures(pub Map<SignerKey, Option<Signature>>);

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Recovery{
    pub signers: Vec<Signer>, // Maximum 255 signers because it doesn't make sense to have more
    pub conditions: Vec<Condition>
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Condition {
    pub allowed_signers_index: Bytes, // Each byte is the index of the signer + Assuming if this is empty we use all the signers
    pub threshold: BytesN<1>,
    pub inactivity_time: u64
}
