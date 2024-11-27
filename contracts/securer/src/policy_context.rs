use soroban_sdk::{
    auth::{Context, ContractContext}, symbol_short, Address, Env, Vec
};



/**
 * Remove the current context for the policy__ call
 * This is done to avoid impossible state where the contexts passed as an argument contain the policy context.
 * Indeed, when the policy is doing authentication, we cannot deterministically determined the proper Context again
 * because the Context argument modifies the Context.
 * 
 * Example in pseudo-code: 
 * ``````
 * fn policy__(..., [this_policy_context, ...]){
 *        env.current_contract_address().require_auth_for_args(([this_policy_context]))
 * }
 * ``````
 * => This mean the context of the SW contain the sub-invocation of the policy__ function which is "this_policy_context"
 * But this require_auth_for_args create a NEW Context "policy_context_2" with the "this_policy_context" as args
 * But that means we need the SW to contain the sub-invocation with "policy_context_2" but that leads to an infinite loop.
 * (Because we now the require_auth_for_args will create a new context "policy_context_3" with "policy_context_2" as args and so on)
 * 
 * 
 * Access to this removed context is still possible with a `__check_auth` function. This is what we are doing
 */
pub fn filter_policy_context(env: &Env, contexts: &Vec<Context>, policy_address: &Address) -> Vec<Context> {
    let mut contexts_without_policy = Vec::new(env);
    for context in contexts.iter() {
        if !is_policy_context(&context, policy_address) {
            contexts_without_policy.push_back(context);
        }
    }
    contexts_without_policy
}



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
