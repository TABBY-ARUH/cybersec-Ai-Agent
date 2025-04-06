use candid::{CandidType, Deserialize};
use ic_cdk::api::management_canister::http_request::{
    http_request, CanisterHttpRequestArgument, HttpHeader, HttpMethod, TransformArgs,
    TransformContext,
};
use ic_cdk_macros::{query, update};
use serde::Serialize;
use std::cell::RefCell;
use std::collections::HashMap;
use std::error::Error;

#[derive(CandidType, Deserialize, Serialize, Clone, Debug)]
pub struct LogEntry {
    pub message: String,
    pub timestamp: u64,
    pub source: String,
}

#[derive(CandidType, Deserialize, Serialize, Clone, Debug)]
pub struct ThreatDetectionResult {
    pub is_threat: bool,
    pub confidence: f64,
    pub category: String,
    pub details: String,
}

thread_local! {
    static BASELINE_STATS: RefCell<HashMap<String, f64>> = RefCell::new(HashMap::new());
    static KEYWORD_THREATS: RefCell<Vec<String>> = RefCell::new(vec![
        "injection".to_string(), "overflow".to_string(), "exploit".to_string(),
        "malware".to_string(), "unauthorized".to_string(), "brute force".to_string(),
        "ddos".to_string(), "xss".to_string(), "csrf".to_string(), "backdoor".to_string(),
    ]);
}

#[update]
pub fn detect_threats(logs: Vec<LogEntry>) -> Vec<ThreatDetectionResult> {
    logs.into_iter().map(analyze_log_entry).collect()
}

fn analyze_log_entry(log: LogEntry) -> ThreatDetectionResult {
    let mut is_threat = false;
    let mut confidence = 0.0;
    let mut category = "normal".to_string();
    let mut details = "No threat detected".to_string();

    KEYWORD_THREATS.with(|keywords| {
        if let Some(keyword) = keywords.borrow().iter().find(|&kw| log.message.to_lowercase().contains(kw)) {
            is_threat = true;
            confidence = 0.7;
            category = "suspicious_activity".to_string();
            details = format!("Suspicious keyword detected: {}", keyword);
        }
    });

    if !is_threat {
        let source_frequency = update_source_frequency(&log.source);
        if source_frequency > 10.0 {
            is_threat = true;
            confidence = 0.6;
            category = "unusual_frequency".to_string();
            details = format!("Unusual activity frequency from source: {}", log.source);
        }
    }

    ThreatDetectionResult { is_threat, confidence, category, details }
}

fn update_source_frequency(source: &str) -> f64 {
    BASELINE_STATS.with(|stats| {
        let mut stats_map = stats.borrow_mut();
        let count = stats_map.entry(source.to_string()).or_insert(0.0);
        *count += 1.0;
        *count
    })
}

#[update]
pub async fn analyze_content_with_ai(logs: Vec<LogEntry>) -> Result<Vec<ThreatDetectionResult>, String> {
    let basic_results = detect_threats(logs.clone());
    let suspicious_logs: Vec<LogEntry> = logs.into_iter()
        .zip(&basic_results)
        .filter(|(_, result)| result.confidence < 0.8 && result.confidence > 0.4)
        .map(|(log, _)| log)
        .collect();
    
    if suspicious_logs.is_empty() {
        return Ok(basic_results);
    }
    
    // Placeholder: Add HTTP request logic for AI-based analysis
    Ok(basic_results)
}

#[update]
pub async fn analyze_with_onchain_model(logs: Vec<LogEntry>) -> Vec<ThreatDetectionResult> {
    let mut results = Vec::new();
    for log in logs {
        let prompt = format!("Analyze this log entry for security threats: {}\nSource: {}", log.message, log.source);
        let response = "Placeholder response"; // Replace with AI model integration
        let category = if response.contains("injection") {
            "sql_injection".to_string()
        } else if response.contains("ddos") {
            "ddos_attack".to_string()
        } else {
            "unknown_threat".to_string()
        };
        results.push(ThreatDetectionResult { is_threat: response.contains("threat"), confidence: 0.85, category, details: response.to_string() });
    }
    results
}