use soroban_sdk::{
    auth::{Context, ContractContext}, symbol_short, Address, Env, Vec
};


/**
 * Check if the current context is the policy context that will be called
 * This is done to avoid impossible state where the context passed as an argument is the policy context
 * Which in case the policy is doing authentication, cannot be determined because it modifies the context itself 
 * in the AuthorizationInvocation
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

pub fn filter_policy_context(env: &Env, contexts: &Vec<Context>, policy_address: &Address) -> Vec<Context> {
    let mut context_without_policy = Vec::new(env);
    for context in contexts.iter() {
        if !is_policy_context(&context, policy_address) {
            context_without_policy.push_back(context);
        }
    }
    context_without_policy
}