#![no_std]
//! Inner fixture contract. `transfer` has the SEP-41 argument shape
//! (from, to, amount) so the AuthMatrix decoder maps it, but it moves no
//! funds: it only requires `from`'s authorization and returns `amount`.
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Inner;

#[contractimpl]
impl Inner {
    pub fn transfer(_env: Env, from: Address, _to: Address, amount: i128) -> i128 {
        from.require_auth();
        amount
    }
}
