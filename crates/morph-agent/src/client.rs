use std::time::Duration;

use reqwest::{Client, Url};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use thiserror::Error;

use crate::http_safety::{is_secure_service_url, read_response_limited};
use crate::{
    CredentialVerifyRequest, FairExchangeClaim, FairExchangeClaimRequest, FairExchangeEnvelope,
    FairExchangeOfferRequest, PayRequest, PayResponse, PaymentRequirements, SettleRequest,
    SettleResponse, VerifyRequest, VerifyResponse,
};

const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum AgentClientError {
    #[error("invalid Morph Agent URL")]
    InvalidUrl,
    #[error("invalid Morph Agent API bearer token")]
    InvalidBearerToken,
    #[error("Morph Agent transport failed: {0}")]
    Transport(String),
    #[error("Morph Agent returned HTTP {status}: {message}")]
    Http { status: u16, message: String },
    #[error("Morph Agent returned an invalid or oversized response")]
    InvalidResponse,
}

/// Native Rust SDK for an independent Morph Agent sidecar. It contains no
/// Fiber internals and therefore works with an unmodified Fiber RPC server.
#[derive(Clone)]
pub struct AgentClient {
    base_url: Url,
    client: Client,
    bearer_token: Option<String>,
}

impl AgentClient {
    pub fn new(base_url: &str) -> Result<Self, AgentClientError> {
        let mut base_url = Url::parse(base_url).map_err(|_| AgentClientError::InvalidUrl)?;
        if !is_secure_service_url(&base_url) {
            return Err(AgentClientError::InvalidUrl);
        }
        if !base_url.path().ends_with('/') {
            base_url.set_path(&format!("{}/", base_url.path()));
        }
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| AgentClientError::Transport(error.to_string()))?;
        Ok(Self {
            base_url,
            client,
            bearer_token: None,
        })
    }

    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Result<Self, AgentClientError> {
        let token = token.into();
        if token.len() < 32 {
            return Err(AgentClientError::InvalidBearerToken);
        }
        self.bearer_token = Some(token);
        Ok(self)
    }

    pub async fn supported(&self) -> Result<Value, AgentClientError> {
        self.get("v1/supported").await
    }

    pub async fn create_challenge<T: Serialize + ?Sized>(
        &self,
        request: &T,
    ) -> Result<PaymentRequirements, AgentClientError> {
        self.post("v1/challenges", request).await
    }

    pub async fn pay(&self, request: &PayRequest) -> Result<PayResponse, AgentClientError> {
        self.post("v1/pay", request).await
    }

    pub async fn verify(
        &self,
        request: &VerifyRequest,
    ) -> Result<VerifyResponse, AgentClientError> {
        self.post("v1/x402/verify", request).await
    }

    pub async fn settle(
        &self,
        request: &SettleRequest,
    ) -> Result<SettleResponse, AgentClientError> {
        self.post("v1/x402/settle", request).await
    }

    pub async fn verify_credential(
        &self,
        request: &CredentialVerifyRequest,
    ) -> Result<Value, AgentClientError> {
        self.post("v1/credentials/verify", request).await
    }

    pub async fn create_fair_offer(
        &self,
        request: &FairExchangeOfferRequest,
    ) -> Result<FairExchangeEnvelope, AgentClientError> {
        self.post("v1/fair-exchange/offers", request).await
    }

    pub async fn claim_fair_offer(
        &self,
        request: &FairExchangeClaimRequest,
    ) -> Result<FairExchangeClaim, AgentClientError> {
        self.post("v1/fair-exchange/claims", request).await
    }

    pub async fn payments(&self, limit: usize) -> Result<Value, AgentClientError> {
        self.get(&format!("v1/payments?limit={limit}")).await
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, AgentClientError> {
        let url = self
            .base_url
            .join(path)
            .map_err(|_| AgentClientError::InvalidUrl)?;
        let mut request = self.client.get(url);
        if let Some(token) = &self.bearer_token {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .map_err(|error| AgentClientError::Transport(error.to_string()))?;
        decode_response(response).await
    }

    async fn post<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, AgentClientError> {
        let url = self
            .base_url
            .join(path)
            .map_err(|_| AgentClientError::InvalidUrl)?;
        let mut request = self.client.post(url).json(body);
        if let Some(token) = &self.bearer_token {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .map_err(|error| AgentClientError::Transport(error.to_string()))?;
        decode_response(response).await
    }
}

async fn decode_response<T: DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, AgentClientError> {
    let status = response.status();
    let bytes = read_response_limited(response, MAX_RESPONSE_BYTES)
        .await
        .map_err(|error| AgentClientError::Transport(error.to_string()))?
        .ok_or(AgentClientError::InvalidResponse)?;
    if !status.is_success() {
        let message = serde_json::from_slice::<Value>(&bytes)
            .ok()
            .and_then(|value| {
                value
                    .get("error")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "request failed".to_string());
        return Err(AgentClientError::Http {
            status: status.as_u16(),
            message,
        });
    }
    serde_json::from_slice(&bytes).map_err(|_| AgentClientError::InvalidResponse)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_requires_tls_for_non_loopback_agents() {
        for accepted in [
            "http://localhost:4617",
            "http://127.0.0.1:4617",
            "http://[::1]:4617",
            "https://agent.example.com",
        ] {
            assert!(AgentClient::new(accepted).is_ok(), "{accepted}");
        }
        for rejected in ["http://example.com", "http://10.0.0.8:4617"] {
            assert!(
                matches!(
                    AgentClient::new(rejected),
                    Err(AgentClientError::InvalidUrl)
                ),
                "{rejected}"
            );
        }
    }

    #[test]
    fn client_rejects_short_api_tokens() {
        assert!(matches!(
            AgentClient::new("http://127.0.0.1:4617")
                .unwrap()
                .with_bearer_token("short"),
            Err(AgentClientError::InvalidBearerToken)
        ));
    }
}
