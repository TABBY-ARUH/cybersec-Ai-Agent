use crate::api::LogEntry;
use candid::CandidType;
use ic_cdk::println;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, CandidType)]
pub struct ThreatDetectionResult {
    pub category: String,
    pub severity: String,
    pub confidence: f64,
    pub details: String,
}

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
    "principal id theft",
];

const IC_VULNERABILITIES: [&str; 8] = [
    "vetkd exploit",
    "encrypted-notes vulnerability",
    "deterministic encryption",
    "reused key pair",
    "session timeout",
    "symmetric key",
    "unauthorized delegation",
    "canister call injection",
];

pub fn detect_threats(logs: Vec<LogEntry>) -> Vec<ThreatDetectionResult> {
    let mut threats = Vec::new();

    for log in logs {
        let mut detected_threat: Option<ThreatDetectionResult> = None;

        if log.message.to_lowercase().contains("malware") {
            detected_threat = Some(ThreatDetectionResult {
                category: "Malware".to_string(),
                severity: "HIGH".to_string(),
                confidence: 0.85,
                details: format!("Malware threat detected in: {}", log.message),
            });
        }

        for threat in CRYPTO_THREATS.iter() {
            if log.message.to_lowercase().contains(&threat.to_lowercase()) {
                detected_threat = Some(ThreatDetectionResult {
                    category: "Crypto/Blockchain Threat".to_string(),
                    severity: analyze_threat_severity(threat),
                    confidence: 0.9,
                    details: format!("Detected: {} in {}", threat, log.message),
                });
                println!("Critical crypto threat detected: {}", threat);
                break;
            }
        }

        for vuln in IC_VULNERABILITIES.iter() {
            if log.message.to_lowercase().contains(&vuln.to_lowercase()) {
                detected_threat = Some(ThreatDetectionResult {
                    category: "IC Vulnerability".to_string(),
                    severity: analyze_threat_severity(vuln),
                    confidence: 0.8,
                    details: format!("Detected IC vulnerability: {} in {}", vuln, log.message),
                });
                println!("IC-specific vulnerability detected: {}", vuln);
                break;
            }
        }

        if let Some(threat) = detected_threat {
            threats.push(threat);
        }
    }
    threats
}

pub fn analyze_threat_severity(threat: &str) -> String {
    if ["private key", "seed phrase", "principal id theft"]
        .iter()
        .any(|&t| threat.contains(t))
    {
        "CRITICAL".to_string()
    } else if ["canister", "cycle", "delegation"]
        .iter()
        .any(|&t| threat.contains(t))
    {
        "HIGH".to_string()
    } else {
        "MEDIUM".to_string()
    }
}
