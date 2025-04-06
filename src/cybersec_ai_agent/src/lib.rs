use candid::{CandidType, Deserialize};
use ic_cdk::api::management_canister::http_request::{HttpHeader, HttpResponse};
use ic_cdk_macros::{init, query, update};

// Import your modules
mod api;
mod threat_detection;
mod wallet;

#[derive(CandidType, Deserialize)]
struct HttpRequest {
    method: String,
    url: String,
    headers: Vec<HttpHeader>,
    body: Vec<u8>,
}

// Initialize the canister
#[init]
fn init() {
    ic_cdk::println!("CyberSec AI Agent Backend initialized");
}

// HTTP request handler for queries
#[query]
fn http_request(req: HttpRequest) -> HttpResponse {
    handle_http_request(req, false)
}

// HTTP request handler for updates, renamed to avoid symbol conflict
#[update]
fn http_request_update_v2(req: HttpRequest) -> HttpResponse {
    handle_http_request(req, true)
}

// Common handler for HTTP requests
fn handle_http_request(req: HttpRequest, is_update: bool) -> HttpResponse {
    let path = req.url.split('?').next().unwrap_or("");

    // Route the request based on the path
    if path.contains("/threat_endpoint") && req.method == "POST" {
        if !is_update {
            // For query calls, we need to upgrade to update call
            return HttpResponse {
                status: 200u16.into(), // Convert u16 to Nat
                headers: vec![
                    HttpHeader {
                        name: "IC-Certificate".to_string(),
                        value: "".to_string(),
                    },
                    HttpHeader {
                        name: "upgrade".to_string(),
                        value: "true".to_string(),
                    },
                ],
                body: vec![],
            };
        }

        // Parse the request body as LogEntry array
        match serde_json::from_slice::<Vec<api::LogEntry>>(&req.body) {
            Ok(logs) => {
                let results = threat_detection::detect_threats(logs);
                let response_body = serde_json::to_vec(&results).unwrap_or_default();

                HttpResponse {
                    status: 200u16.into(), // Convert u16 to Nat
                    headers: vec![HttpHeader {
                        name: "Content-Type".to_string(),
                        value: "application/json".to_string(),
                    }],
                    body: response_body,
                }
            }
            Err(_) => {
                HttpResponse {
                    status: 400u16.into(), // Convert u16 to Nat
                    headers: vec![HttpHeader {
                        name: "Content-Type".to_string(),
                        value: "text/plain".to_string(),
                    }],
                    body: "Invalid request body".as_bytes().to_vec(),
                }
            }
        }
    } else if path.contains("/wallet_authenticate") && req.method == "POST" {
        // Similar handling for wallet authentication

        HttpResponse {
            status: 200u16.into(), // Convert u16 to Nat
            headers: vec![HttpHeader {
                name: "Content-Type".to_string(),
                value: "application/json".to_string(),
            }],
            body: "Authentication successful".as_bytes().to_vec(),
        }
    } else {
        // Not found
        HttpResponse {
            status: 404u16.into(), // Convert u16 to Nat
            headers: vec![HttpHeader {
                name: "Content-Type".to_string(),
                value: "text/plain".to_string(),
            }],
            body: "Not Found".as_bytes().to_vec(),
        }
    }
}

// Direct canister method for threat detection
#[update]
fn detect_threats(logs: Vec<api::LogEntry>) -> Vec<String> {
    threat_detection::detect_threats(logs)
}

// Export Candid interface
ic_cdk::export_candid!();
