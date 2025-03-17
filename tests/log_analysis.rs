// tests/log_analysis.rs
use cybersec_ai_agent_backend::api::LogEntry;
use cybersec_ai_agent_backend::threat_detection::detect_threats;

#[test]
fn test_analyze_logs() {
    let logs = vec![LogEntry {
        message: "Malware detected".to_string(),
    }];

    let result = detect_threats(logs);

    assert_eq!(result, vec!["Threat found: Malware detected"]);
}