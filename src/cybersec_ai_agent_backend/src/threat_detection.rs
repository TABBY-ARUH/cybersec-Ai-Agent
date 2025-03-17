use crate::api::LogEntry;
use ic_cdk::println;

// Define common blockchain and cryptography threat patterns
const CRYPTO_THREATS: [&str; 12] = [
    "private key",
    "seed phrase",
    "wallet compromise",
    "key leak",
    "unauthorized transfer",
    "replay attack",
    "front-running",
    "malicious MEV",
    "threshold signature",
    "canister exploit",
    "cycle drain",
    "principal id theft"
];

// Define Internet Computer specific vulnerabilities
const IC_VULNERABILITIES: [&str; 8] = [
    "vetkd exploit",
    "encrypted-notes vulnerability",
    "deterministic encryption",
    "reused key pair",
    "session timeout",
    "symmetric key",
    "unauthorized delegation",
    "canister call injection"
];

pub fn detect_threats(logs: Vec<LogEntry>) -> Vec<String> {
    let mut threats = Vec::new();
    
    for log in logs {
        // Check for general malware
        if log.message.to_lowercase().contains("malware") {
            threats.push(format!("Malware threat detected: {}", log.message));
        }
        
        // Check for cryptography and blockchain threats
        for threat in CRYPTO_THREATS.iter() {
            if log.message.to_lowercase().contains(&threat.to_lowercase()) {
                threats.push(format!("Crypto/blockchain threat detected: {} - {}", threat, log.message));
                // Log to the IC console for monitoring
                println!("Critical crypto threat detected: {}", threat);
                break;
            }
        }
        
        // Check for Internet Computer specific vulnerabilities
        for vuln in IC_VULNERABILITIES.iter() {
            if log.message.to_lowercase().contains(&vuln.to_lowercase()) {
                threats.push(format!("Internet Computer vulnerability detected: {} - {}", vuln, log.message));
                // Log to the IC console for monitoring
                println!("IC-specific vulnerability detected: {}", vuln);
                break;
            }
        }
        
        // Check for vetKeys-related security issues based on the knowledge sources
        if log.message.to_lowercase().contains("vetkey") || 
           log.message.to_lowercase().contains("threshold encryption") {
            threats.push(format!("vetKeys security concern: {}", log.message));
        }
    }
    
    threats
}

// Helper function to analyze severity of threats
pub fn analyze_threat_severity(threat: &str) -> &'static str {
    if threat.contains("private key") || 
       threat.contains("seed phrase") || 
       threat.contains("principal id theft") {
        "CRITICAL"
    } else if threat.contains("canister") || 
              threat.contains("cycle") || 
              threat.contains("delegation") {
        "HIGH"
    } else {
        "MEDIUM"
    }
}