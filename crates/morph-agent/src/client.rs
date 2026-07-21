use std::time::Duration;

use reqwest::{Client, Url};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use thiserror::Error;

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
}

impl AgentClient {
    pub fn new(base_url: &str) -> Result<Self, AgentClientError> {
        let mut base_url = Url::parse(base_url).map_err(|_| AgentClientError::InvalidUrl)?;
        if !matches!(base_url.scheme(), "http" | "https") || base_url.host_str().is_none() {
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
        Ok(Self { base_url, client })
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
        let response = self
            .client
            .get(url)
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
        let response = self
            .client
            .post(url)
            .json(body)
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
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(AgentClientError::InvalidResponse);
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|error| AgentClientError::Transport(error.to_string()))?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(AgentClientError::InvalidResponse);
    }
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
