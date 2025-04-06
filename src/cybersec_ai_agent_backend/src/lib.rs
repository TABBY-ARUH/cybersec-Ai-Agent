use candid::{CandidType, Deserialize, Func, Principal};
use num_traits::cast::ToPrimitive;
use ic_cdk::api::management_canister::http_request::{
    HttpResponse, HttpHeader, HttpMethod, CanisterHttpRequestArgument,
};
use ic_cdk::api::call::call;
use ic_cdk::{query, update};
use serde::{Serialize, Serializer};
use serde_bytes;
use std::cell::RefCell;
use std::collections::HashMap;

mod api;
mod wallet;

// Define CallError if it's not in wallet module
#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum CallError {
    InvalidArgument(String),
    CanisterError(String),
    NetworkError(String),
}

// Define missing types
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct ThreatInput {
    pub source: String,
    pub message: String,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct ThreatOutput {
    pub is_threat: bool,
    pub details: String,
    pub category: String,
    pub confidence: f64,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct ScanResult {
    pub port: u16,
    pub open: bool,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct VulnerabilityResult {
    pub cve_id: String,
    pub severity: String,
    pub description: String,
    pub remediation: String,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct CanisterSecurityCheck {
    pub canister_id: String,
    pub issues: Vec<String>,
    pub risk_level: String,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct SecurityLog {
    pub timestamp: u64,
    pub event_type: String,
    pub details: String,
    pub severity: String,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct NetworkScan {
    pub target: String,
    pub open_ports: Vec<u16>,
    pub services: Vec<String>,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct AnomalyDetectionResult {
    pub is_anomaly: bool,
    pub confidence: f64,
    pub explanation: String,
}

// Add thread_local variables
thread_local! {
    static THREATS: RefCell<HashMap<String, u32>> = RefCell::new(HashMap::new());
    static LOGS: RefCell<Vec<String>> = RefCell::new(Vec::new());
    static SECURITY_LOGS: RefCell<Vec<SecurityLog>> = RefCell::new(Vec::new());
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct CallbackFunc {
    pub function: Func,
    #[serde(with = "serde_bytes")]
    pub environment: Vec<u8>,
}

impl Serialize for CallbackFunc {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("CallbackFunc", 2)?;
        let (principal, method) = (&self.function.principal, &self.function.method);
        state.serialize_field("function", &format!("{}:{}", principal, method))?;
        state.serialize_field("environment", &self.environment)?;
        state.end()
    }
}

#[derive(CandidType, Deserialize, Serialize, Clone, Debug)]
pub enum StreamingStrategy {
    Callback {
        callback: CallbackFunc,
        token: String,
    },
}

#[derive(CandidType, Deserialize, Serialize, Clone, Debug)]
pub struct CustomHttpResponse {
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub streaming_strategy: Option<StreamingStrategy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upgrade: Option<bool>,
}

#[derive(CandidType, Deserialize, Serialize, Clone, Debug)]
pub struct HttpRequest {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_response_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transform: Option<(Principal, String)>,
}

// Fix the From implementation to convert Nat to u16
impl From<HttpResponse> for CustomHttpResponse {
    fn from(response: HttpResponse) -> Self {
        CustomHttpResponse {
            status_code: response.status.0.to_u64().unwrap_or(200) as u16,
            headers: response.headers.iter().map(|h| (h.name.clone(), h.value.clone())).collect(),
            body: response.body.clone(),
            streaming_strategy: None,
            upgrade: None,
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

#[query]
fn detect_threats(inputs: Vec<ThreatInput>) -> Vec<ThreatOutput> {
    inputs.iter().map(|input| {
        let is_threat = input.message.contains("attack")
            || input.message.contains("exploit")
            || input.message.contains("injection");

        ThreatOutput {
            is_threat,
            details: if is_threat {
                format!("Potential threat detected in message from {}", input.source)
            } else {
                "No threat detected".to_string()
            },
            category: if is_threat { "SECURITY".to_string() } else { "INFO".to_string() },
            confidence: if is_threat { 0.85 } else { 0.95 },
        }
    }).collect()
}

#[update]
async fn scan_port(ip: String, port: u16) -> ScanResult {
    let url = format!("http://{}:{}/", ip, port);
    let headers = vec![HttpHeader {
        name: "User-Agent".to_string(),
        value: "IC-SecurityScanner".to_string(),
    }];

    let request = CanisterHttpRequestArgument {
        url,
        method: HttpMethod::GET,
        body: None,
        max_response_bytes: Some(1024),
        transform: None,
        headers,
    };

    match call::<(CanisterHttpRequestArgument,), (HttpResponse,)>(
        Principal::management_canister(),
        "http_request",
        (request,),
    )
    .await
    {
        Ok((_response,)) => ScanResult { port, open: true },
        Err((code, message)) => {
            ic_cdk::println!("Port scan error: {:?} - {}", code, message);
            ScanResult { port, open: false }
        }
    }
}

#[update]
async fn fetch_threat_intelligence(ip: String) -> String {
    let url = format!("https://api.abuseipdb.com/api/v2/check?ipAddress={}", ip);
    let headers = vec![HttpHeader {
        name: "User-Agent".to_string(),
        value: "IC-SecurityAgent".to_string(),
    }];

    let request = CanisterHttpRequestArgument {
        url,
        method: HttpMethod::GET,
        body: None,
        max_response_bytes: Some(10_000),
        transform: None,
        headers,
    };

    match call::<(CanisterHttpRequestArgument,), (HttpResponse,)>(
        Principal::management_canister(),
        "http_request",
        (request,),
    )
    .await
    {
        Ok((response,)) => String::from_utf8(response.body).unwrap_or_else(|_| "Error decoding response".to_string()),
        Err((code, message)) => format!("Error fetching threat data: {:?} - {}", code, message),
    }
}

#[update]
async fn check_vulnerabilities(software: String, version: String) -> Vec<VulnerabilityResult> {
    vec![
        VulnerabilityResult {
            cve_id: "CVE-2023-1234".to_string(),
            severity: "High".to_string(),
            description: format!("Buffer overflow in {} version {}", software, version),
            remediation: "Update to latest version".to_string(),
        }
    ]
}

#[update]
async fn analyze_canister_security(canister_id: Principal) -> CanisterSecurityCheck {
    CanisterSecurityCheck {
        canister_id: canister_id.to_string(),
        issues: vec![
            "Unrestricted update calls".to_string(),
            "No caller validation".to_string(),
        ],
        risk_level: "Medium".to_string(),
    }
}

#[update]
fn log_security_event(event_type: String, details: String, severity: String) {
    let log = SecurityLog {
        timestamp: ic_cdk::api::time(),
        event_type,
        details,
        severity,
    };
    
    SECURITY_LOGS.with(|logs| logs.borrow_mut().push(log));
}

#[query]
fn get_security_logs() -> Vec<SecurityLog> {
    SECURITY_LOGS.with(|logs| logs.borrow().clone())
}

#[update]
async fn scan_network(target: String, port_range: (u16, u16)) -> NetworkScan {
    let mut open_ports = Vec::new();
    let mut services = Vec::new();
    
    for port in port_range.0..=port_range.1 {
        let result = scan_port(target.clone(), port).await;
        if result.open {
            open_ports.push(port);
            services.push(format!("Unknown service on port {}", port));
        }
    }
    
    NetworkScan {
        target,
        open_ports,
        services,
    }
}

#[query]
fn detect_anomalies(data_points: Vec<f64>) -> AnomalyDetectionResult {
    let mean = data_points.iter().sum::<f64>() / data_points.len() as f64;
    let variance = data_points.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / data_points.len() as f64;
    let std_dev = variance.sqrt();
    
    let anomalies = data_points.iter().filter(|x| (*x - mean).abs() > 2.0 * std_dev).count();
    
    AnomalyDetectionResult {
        is_anomaly: anomalies > 0,
        confidence: if anomalies > 0 { 0.8 } else { 0.9 },
        explanation: if anomalies > 0 {
            format!("Found {} data points outside 2 standard deviations", anomalies)
        } else {
            "No anomalies detected".to_string()
        },
    }
}

ic_cdk::export_candid!();
