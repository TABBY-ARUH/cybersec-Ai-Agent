use candid::{CandidType, Deserialize, Func, Principal};
use ic_cdk::api::management_canister::http_request::HttpResponse;
use serde::{Serialize, Serializer};
use serde_bytes;
use num_traits::cast::ToPrimitive;

// Define a token type for streaming callbacks
#[derive(CandidType, Deserialize, Serialize, Clone, Debug)]
pub struct HttpResponseStreamingCallbackToken {
    pub token: String,
    // Add any other fields you need
}

// Define CallbackFunc with proper serialization
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct CallbackFunc {
    pub function: Func,
    #[serde(with = "serde_bytes")]
    pub environment: Vec<u8>,
}

// Implement custom serialization for CallbackFunc
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

// Define StreamingStrategy
#[derive(CandidType, Deserialize, Serialize, Clone, Debug)]
pub enum StreamingStrategy {
    Callback {
        callback: CallbackFunc,
        token: HttpResponseStreamingCallbackToken,
    },
}

// Define a Custom HttpResponse structure to avoid name conflict
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

// Define HttpRequest structure
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

// Convert IC HttpResponse to CustomHttpResponse
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