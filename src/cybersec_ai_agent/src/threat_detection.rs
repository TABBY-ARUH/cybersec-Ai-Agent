
use crate::api::LogEntry;

pub fn detect_threats(logs: Vec<LogEntry>) -> Vec<String> {
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
