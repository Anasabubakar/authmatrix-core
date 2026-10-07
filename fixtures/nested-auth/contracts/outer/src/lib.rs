#![no_std]
//! Outer fixture contract. `relay` requires `from`'s authorization for the
//! outer call, then calls `inner.transfer(from, to, amount)`, which requires
//! `from`'s authorization again for the nested invocation. `relay_alt` is an
//! identically-shaped second function used to build "function name" mutations.
use soroban_sdk::{contract, contractimpl, Address, Env, IntoVal, Symbol, Val, Vec};

#[contract]
pub struct Outer;

fn forward(env: &Env, inner: &Address, from: &Address, to: &Address, amount: i128) -> i128 {
    let args: Vec<Val> = (from.clone(), to.clone(), amount).into_val(env);
    env.invoke_contract::<i128>(inner, &Symbol::new(env, "transfer"), args)
}

#[contractimpl]
impl Outer {
    pub fn relay(env: Env, inner: Address, from: Address, to: Address, amount: i128) -> i128 {
        from.require_auth();
        forward(&env, &inner, &from, &to, amount)
    }

    pub fn relay_alt(env: Env, inner: Address, from: Address, to: Address, amount: i128) -> i128 {
        from.require_auth();
        forward(&env, &inner, &from, &to, amount)
    }
}

#[cfg(test)]
mod test;
