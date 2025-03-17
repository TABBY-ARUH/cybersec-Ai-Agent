use candid::{CandidType, Deserialize};
use ic_cdk::{query, update};
use serde::Serialize;
use std::cell::RefCell;
use std::collections::HashMap;

// Import the HTTP types from api.rs
use crate::api::{HttpRequest, HttpResponse, http_request, http_request_update};

// Module declarations
mod api;
mod threat_detection;
mod wallet;

// Define the LogEntry struct that was missing
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct LogEntry {
    timestamp: String,
    source_ip: String,
    action: String,
    status: String,
    details: String,
}

// Request and response structures
#[derive(CandidType, Deserialize)]
struct AnalyzeLogsRequest {
    body: Vec<u8>,
}

#[derive(CandidType, Serialize)]
struct AnalyzeLogsResponse {
    threats: Vec<String>,
}

// State management
thread_local! {
    static LOGS: RefCell<Vec<LogEntry>> = RefCell::new(Vec::new());
    static THREATS: RefCell<HashMap<String, u32>> = RefCell::new(HashMap::new());
}

#[update]
async fn analyze_logs(req: AnalyzeLogsRequest) -> AnalyzeLogsResponse {
    // Attempt to deserialize the logs
    match candid::decode_one::<Vec<LogEntry>>(&req.body) {
        Ok(logs) => {
            let results = detect_threats(logs);
            AnalyzeLogsResponse { threats: results }
        }
        Err(e) => {
            ic_cdk::println!("Error deserializing logs: {:?}", e);
            AnalyzeLogsResponse { threats: vec!["Error processing logs".to_string()] }
        }
    }
}

#[query]
fn get_threat_summary() -> HashMap<String, u32> {
    THREATS.with(|threats| threats.borrow().clone())
}

#[update]
fn clear_logs() {
    LOGS.with(|logs| logs.borrow_mut().clear());
}

#[update]
fn add_log(log: LogEntry) {
    LOGS.with(|logs| logs.borrow_mut().push(log.clone()));
    
    // Check for threats in the new log
    let threats = detect_threats(vec![log]);
    
    // Update threat counts
    if !threats.is_empty() {
        THREATS.with(|t| {
            let mut threat_map = t.borrow_mut();
            for threat in threats {
                *threat_map.entry(threat).or_insert(0) += 1;
            }
        });
    }
}

// Implementation of the detect_threats function
fn detect_threats(logs: Vec<LogEntry>) -> Vec<String> {
    let mut threats = Vec::new();
    
    for log in logs {
        // Simple threat detection logic
        if log.status == "FAILED" && log.action == "LOGIN" {
            threats.push(format!("Failed login attempt from IP: {}", log.source_ip));
        }
        
        if log.details.contains("SQL injection") || log.details.contains("XSS") {
            threats.push(format!("Potential attack detected: {} from IP: {}", 
                                log.details, log.source_ip));
        }
    }
    
    threats
}

// Export Candid interface
ic_cdk::export_candid!();