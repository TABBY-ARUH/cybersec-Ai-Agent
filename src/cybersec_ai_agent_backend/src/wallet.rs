use candid::Principal;
use ic_cdk::api::call::{call, RejectionCode};
use ic_cdk::{query, update};
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;

// Use thread_local instead of lazy_static for IC canisters
thread_local! {
    static WALLET_STORE: RefCell<HashMap<Principal, String>> = RefCell::new(HashMap::new());
}

// Define a custom error type that implements both Error and CandidType
#[derive(candid::CandidType, Debug)]
pub struct CallError {
    code: RejectionCode,
    message: String,
}

impl CallError {
    pub fn new(code: RejectionCode, message: String) -> Self {
        CallError { code, message }
    }
}

impl fmt::Display for CallError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Call error (code: {:?}): {}", self.code, self.message)
    }
}

impl std::error::Error for CallError {}

#[update]
async fn verify_user(user_wallet: Principal) -> Result<(), CallError> {
    let result: Result<(), (RejectionCode, String)> =
        call::<(Principal,), ()>(user_wallet, "verifyUser", (user_wallet,)).await;

    match result {
        Ok(()) => {
            ic_cdk::println!("Verification successful for user: {:?}", user_wallet);
            // Use with() to access thread_local storage
            WALLET_STORE.with(|store| {
                store
                    .borrow_mut()
                    .insert(user_wallet, "Verified".to_string());
            });
            Ok(())
        }
        Err((code, msg)) => {
            ic_cdk::println!("Verification failed: {:?} - {}", code, msg);
            Err(CallError::new(code, msg))
        }
    }
}

#[query]
fn get_wallet_info(user_wallet: Principal) -> String {
    // Use with() to access thread_local storage
    WALLET_STORE.with(|store| {
        let store = store.borrow();
        match store.get(&user_wallet) {
            Some(status) => format!("Wallet information for {}: {}", user_wallet, status),
            None => format!("No information found for wallet: {}", user_wallet),
        }
    })
}
