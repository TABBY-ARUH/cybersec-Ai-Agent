use candid::{CandidType, Deserialize};
use ic_cdk_macros::{query, update};
use serde::Serialize;
use crate::threat_detection::detect_threats;

#[derive(CandidType, Deserialize, Serialize, Debug)]
pub struct LogEntry {
    pub message: String,
}

// Simplified HTTP response without streaming to avoid serialization issues
#[derive(CandidType, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub streaming_strategy: Option<()>, // Using unit type to avoid candid::Func serialization issues
    pub upgrade: Option<bool>,
}

#[derive(CandidType, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub certificate_version: Option<u16>,
}

// Standard http_request method as required by IC
#[query]
pub fn http_request(req: HttpRequest) -> HttpResponse {
    handle_request(req, false)
}

// Update method for state-changing operations
#[update]
pub fn http_request_update(req: HttpRequest) -> HttpResponse {
    handle_request(req, true)
}

pub fn handle_request(req: HttpRequest, is_update: bool) -> HttpResponse {
    // Only process POST requests to /threat_endpoint
    if req.method == "POST" && req.url.contains("/threat_endpoint") {
        if !is_update {
            // For query calls, we need to upgrade to update call
            return HttpResponse {
                status_code: 200,
                headers: vec![("Content-Type".to_string(), "application/json".to_string())],
                body: vec![],
                streaming_strategy: None,
                upgrade: Some(true),
            };
        }
        
        // Parse the request body
        match serde_json::from_slice::<Vec<LogEntry>>(&req.body) {
            Ok(log_entries) => {
                // Process the log entries
                let results = detect_threats(log_entries);
                
                // Return the results as JSON
                let response_body = serde_json::to_vec(&results).unwrap_or_default();
                
                HttpResponse {
                    status_code: 200,
                    headers: vec![
                        ("Content-Type".to_string(), "application/json".to_string()),
                    ],
                    body: response_body,
                    streaming_strategy: None,
                    upgrade: None,
                }
            },
            Err(_) => {
                // Return a 400 Bad Request if the body couldn't be parsed
                HttpResponse {
                    status_code: 400,
                    headers: vec![
                        ("Content-Type".to_string(), "text/plain".to_string()),
                    ],
                    body: "Invalid request body".as_bytes().to_vec(),
                    streaming_strategy: None,
                    upgrade: None,
                }
            }
        }
    } else {
        // Return a 404 Not Found for other routes
        HttpResponse {
            status_code: 404,
            headers: vec![
                ("Content-Type".to_string(), "text/plain".to_string()),
            ],
            body: "Not Found".as_bytes().to_vec(),
            streaming_strategy: None,
            upgrade: None,
        }
    }
}