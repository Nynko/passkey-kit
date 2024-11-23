use soroban_sdk::{
    auth::{Context, ContractContext}, symbol_short, Address, Env, Vec
};


/**
 * Check if the current context is the policy context that will be called
 * This is done to avoid impossible state where the contexts passed as an argument contain the policy context.
 * Indeed, in case the policy is doing authentication, we cannot deterministically determined the proper Context again
 * because the Context argument modifies the context itself in the AuthorizationInvocation.
 * 
 * Access to this removed context is still possible with a `__check_auth` function. 
 */
pub fn is_policy_context( 
    context: &Context,
    policy_address: &Address) -> bool{
    match context {
        Context::Contract(ContractContext { contract, fn_name, .. }) => {
            if contract == policy_address && *fn_name == symbol_short!("policy__") {
                true
            } else {
                false
            }
        }
        _ => false
    }
}

/** See `is_policy_context()` comments to understand why we want to remove the policy__ context */
pub fn filter_policy_context(env: &Env, contexts: &Vec<Context>, policy_address: &Address) -> Vec<Context> {
    let mut contexts_without_policy = Vec::new(env);
    for context in contexts.iter() {
        if !is_policy_context(&context, policy_address) {
            contexts_without_policy.push_back(context);
        }
    }
    contexts_without_policy
}