use candid::Principal;
use ic_cdk::call;
use ic_cdk::api::call::RejectionCode;
use std::error::Error as StdError;

// Define a custom error type to handle call errors
#[derive(Debug)]
struct CallError(RejectionCode, String);

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Call rejected with code {:?}: {}", self.0, self.1)
    }
}

impl StdError for CallError {}

// Define the function for verifying the user
async fn verify_user(user_wallet: Principal) -> Result<(), Box<dyn StdError>> {
    let result: Result<(), (RejectionCode, String)> = call(
        user_wallet,                // Wallet's Principal
        "verifyUser",               // The canister function to call
        (user_wallet,),             // Pass the wallet as a parameter
    ).await;

    match result {
        Ok(()) => {
            ic_cdk::println!("Verification successful");
            Ok(())
        },
        Err((code, msg)) => Err(Box::new(CallError(code, msg))),
    }
}

// Define the function for submitting a transaction
async fn submit_transaction(user_wallet: Principal, action: String) -> Result<(), Box<dyn StdError>> {
    let result: Result<(), (RejectionCode, String)> = call(
        user_wallet,                        // Wallet Principal
        "submitTransaction",                // Canister function to call
        (user_wallet, action),              // Pass wallet and action as parameters
    ).await;

    match result {
        Ok(()) => {
            ic_cdk::println!("Transaction submission successful");
            Ok(())
        },
        Err((code, msg)) => Err(Box::new(CallError(code, msg))),
    }
}