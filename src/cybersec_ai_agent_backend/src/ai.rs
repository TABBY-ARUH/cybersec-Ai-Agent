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

// Store baseline statistics for anomaly detection
thread_local! {
    static BASELINE_STATS: RefCell<HashMap<String, f64>> = RefCell::new(HashMap::new());
    static KEYWORD_THREATS: RefCell<Vec<String>> = RefCell::new(vec![
        "injection".to_string(),
        "overflow".to_string(),
        "exploit".to_string(),
        "malware".to_string(),
        "unauthorized".to_string(),
        "brute force".to_string(),
        "ddos".to_string(),
        "xss".to_string(),
        "csrf".to_string(),
        "backdoor".to_string(),
    ]);
}

// Simple on-chain threat detection
#[update]
fn detect_threats(logs: Vec<LogEntry>) -> Vec<ThreatDetectionResult> {
    logs.iter().map(|log| analyze_log_entry(log)).collect()
}

fn analyze_log_entry(log: &LogEntry) -> ThreatDetectionResult {
    // Simple keyword-based detection
    let mut is_threat = false;
    let mut confidence = 0.0;
    let mut category = "normal".to_string();
    let mut details = "No threat detected".to_string();
    
    KEYWORD_THREATS.with(|keywords| {
        for keyword in keywords.borrow().iter() {
            if log.message.to_lowercase().contains(&keyword.to_lowercase()) {
                is_threat = true;
                confidence = 0.7; // Basic confidence score
                category = "suspicious_activity".to_string();
                details = format!("Suspicious keyword detected: {}", keyword);
                break;
            }
        }
    });
    
    // Simple frequency analysis
    if !is_threat {
        let source_frequency = update_source_frequency(&log.source);
        if source_frequency > 10.0 {
            is_threat = true;
            confidence = 0.6;
            category = "unusual_frequency".to_string();
            details = format!("Unusual activity frequency from source: {}", log.source);
        }
    }
    
    ThreatDetectionResult {
        is_threat,
        confidence,
        category,
        details,
    }
}

fn update_source_frequency(source: &str) -> f64 {
    BASELINE_STATS.with(|stats| {
        let mut stats_map = stats.borrow_mut();
        let count = stats_map.entry(source.to_string()).or_insert(0.0);
        *count += 1.0;
        *count
    })
}

// Your existing HTTP outcall function for more advanced analysis
pub async fn analyze_content_with_ai(logs: Vec<LogEntry>) -> Result<Vec<ThreatDetectionResult>, Box<dyn Error>> {
    // First run the simple on-chain analysis
    let basic_results = detect_threats(logs.clone());
    
    // For logs that need more advanced analysis, use the external API
    let suspicious_logs: Vec<LogEntry> = logs.into_iter()
        .zip(basic_results.iter())
        .filter(|(_, result)| result.confidence < 0.8 && result.confidence > 0.4)
        .map(|(log, _)| log)
        .collect();
    
    if suspicious_logs.is_empty() {
        return Ok(basic_results);
    }
    
    // Add your HTTP outcall implementation here
    // This would complete the analyze_content_with_ai function
    
    Ok(basic_results) // Placeholder return
}

// This should be a separate function, not nested inside analyze_content_with_ai
#[update]
async fn analyze_with_onchain_model(logs: Vec<LogEntry>) -> Vec<ThreatDetectionResult> {
    // Note: ic_llm is a placeholder module that doesn't exist yet
    // You would need to use the actual LLM integration when available
    
    let mut results = Vec::new();
    
    for log in logs {
        // Example of using the LLM canister for analysis
        // This is simplified and would need to be adapted to your specific needs
        let prompt = format!(
            "Analyze this log entry for security threats: {}\nSource: {}", 
            log.message, 
            log.source
        );
        
        // This is a placeholder - you would need to use the actual API
        // let response = ic_llm::prompt(Model::Llama3_1_8B, &prompt).await;
        let response = "Placeholder response"; // Replace with actual implementation
        
        // Process the response to extract threat information
        let result = ThreatDetectionResult {
            is_threat: response.contains("threat") || response.contains("suspicious"),
            confidence: 0.85,
            category: if response.contains("injection") {
                "sql_injection".to_string()
            } else if response.contains("ddos") {
                "ddos_attack".to_string()
            } else {
                "unknown_threat".to_string()
            },
            details: response.to_string(),
        };
        
        results.push(result);
    }
    
    results
}