use super::{error::ApiError, Signature};

use crate::server::client::client_with_connector_timeout;
use http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::time::Duration;
use tari_crypto::ristretto::RistrettoPublicKey;
use tari_crypto::tari_utilities::hex::Hex;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct YatApi {
    api_url: String,
    api_key: String,
    activation_url: String,
    activation_token: String,
}

impl YatApi {
    pub fn new(
        api_url: String,
        api_key: String,
        activation_url: String,
        activation_token: String,
    ) -> Self {
        YatApi {
            api_url,
            api_key,
            activation_url,
            activation_token,
        }
    }

    /// Register a new user
    pub async fn user_create(
        &self,
        alternate_id: String,
        password: String,
    ) -> Result<DisplayUser, ApiError> {
        let client = client_with_connector_timeout(None);
        let json = json!({
            "alternate_id": alternate_id,
            "password": password,
            "source": "Yat Partner API",
        });

        let mut response = client
            .post(format!("{}/users", self.api_url))
            .header("X-Api-Key", self.api_key.as_str())
            .send_json(&json)
            .await
            .map_err(|e| ApiError::SendRequestError(e.to_string()))?;

        // todo: error messages should be improved
        let user: User = match response.status() {
            StatusCode::OK => response.json().await?,
            status => {
                let err: ResponseError = response.json().await?;
                log::error!("User create error ({}): {:?}", status, err);
                return Err(ApiError::HttpError(status.to_string()));
            }
        };

        Ok(user.user)
    }

    /// Activate a given user
    pub async fn user_activate(
        &self,
        user_id: Uuid,
        activation_source: Option<String>,
    ) -> Result<DisplayUser, ApiError> {
        let json = json!({
            "activation_source": activation_source,
        });

        let client = client_with_connector_timeout(None);

        let mut response = client
            .post(format!("{}/activate/{}", self.activation_url, user_id))
            .header("X-Bypass-Token", self.activation_token.as_str())
            .timeout(Duration::from_secs(30))
            .send_json(&json)
            .await
            .map_err(|e| {
                ApiError::SendRequestError(format!(
                    "Failed to activate: {} {}",
                    self.activation_url,
                    e.to_string()
                ))
            })?;

        let user: DisplayUser = match response.status() {
            StatusCode::OK => response.json().await?,
            status => return Err(ApiError::HttpError(status.to_string())),
        };

        Ok(user)
    }

    /// Log in user via alternate_id and password
    pub async fn user_login(
        &self,
        alternate_id: String,
        password: String,
    ) -> Result<Auth, ApiError> {
        let client = client_with_connector_timeout(None);
        let json = json!({
            "alternate_id": alternate_id,
            "password": password,
        });

        let mut response = client
            .post(format!("{}/auth/token", self.api_url))
            .send_json(&json)
            .await
            .map_err(|e| ApiError::SendRequestError(e.to_string()))?;

        // todo: error messages should be improved
        let auth: Auth = match response.status() {
            StatusCode::OK => response.json().await?,
            status => {
                return Err(ApiError::HttpError(format!(
                    "Could not login: {}",
                    status.to_string()
                )))
            }
        };

        Ok(auth)
    }

    /// Get user details, first login, then fetch account details
    pub async fn user_details(
        &self,
        alternate_id: String,
        password: String,
    ) -> Result<(Auth, DisplayUser), ApiError> {
        let auth = self.user_login(alternate_id, password).await?;
        let client = client_with_connector_timeout(None);

        let mut response = client
            .get(format!("{}/account", self.api_url))
            .bearer_auth(auth.access_token.clone())
            .send()
            .await
            .map_err(|e| ApiError::SendRequestError(e.to_string()))?;

        let incoming_user: User = match response.status() {
            StatusCode::OK => response.json().await?,
            status => {
                return Err(ApiError::HttpError(format!(
                    "Current user account details - {}",
                    status.to_string()
                )))
            }
        };

        Ok((auth, incoming_user.user))
    }

    pub async fn user_yats(&self, auth: Auth) -> Result<Vec<String>, ApiError> {
        let client = client_with_connector_timeout(None);

        let mut response = client
            .get(format!("{}/emoji_id", self.api_url))
            .bearer_auth(auth.access_token.clone())
            .send()
            .await
            .map_err(|e| ApiError::SendRequestError(e.to_string()))?;
        let yats: Vec<String> = match response.status() {
            StatusCode::OK => response.json().await?,
            status => {
                return Err(ApiError::HttpError(format!(
                    "Current user yats - {}",
                    status.to_string()
                )))
            }
        };
        Ok(yats)
    }
    /// Request a random Yat for the user
    pub async fn random_yat(
        &self,
        access_token: String,
        code_id: Uuid,
        signature: Signature,
        pubkey: RistrettoPublicKey,
    ) -> Result<DisplayOrder, ApiError> {
        let client = client_with_connector_timeout(None);
        let json = json!({
            "nonce": signature.get_public_nonce().to_hex(),
            "signature": signature.get_signature().to_hex(),
            "pubkey": pubkey.to_hex(),
            "tracking_data": {"source": "Yat Partner API"},
        });

        let mut response = client
            .post(format!("{}/codes/{}/random_yat", self.api_url, code_id))
            .bearer_auth(access_token)
            .send_json(&json)
            .await
            .map_err(|e| {
                ApiError::SendRequestError(format!("Generate Random Yat - {}", e.to_string()))
            })?;

        // todo: error messages should be improved
        let order: DisplayOrder = match response.status() {
            StatusCode::OK => response.json().await?,
            status => return Err(ApiError::HttpError(status.to_string())),
        };

        Ok(order)
    }

    /// Checkout the cart contents for the user
    pub async fn checkout(
        &self,
        access_token: String,
        pubkey: RistrettoPublicKey,
    ) -> Result<DisplayOrder, ApiError> {
        let client = client_with_connector_timeout(None);
        let json = json!({
            "method": "Free",
            "pubkey": pubkey.to_hex(),
            "tracking_data": {"source": "Yat Partner API"},
        });

        let mut response = client
            .post(format!("{}/cart/checkout", self.api_url))
            .bearer_auth(access_token)
            .send_json(&json)
            .await
            .map_err(|e| ApiError::SendRequestError(e.to_string()))?;

        // todo: error messages should be improved
        let order: DisplayOrder = match response.status() {
            StatusCode::OK => response.json().await?,
            status => {
                log::error!("Checkout error ({}): {:?}", status, response.body().await?);
                return Err(ApiError::HttpError(status.to_string()));
            }
        };

        Ok(order)
    }
}

#[derive(Deserialize, Debug, Serialize)]
pub struct User {
    pub user: DisplayUser,
}
#[derive(Deserialize, Debug, Serialize)]
pub struct DisplayUser {
    pub id: Uuid,
    pub alternate_id: String,
    pub is_active: bool,
    pub pubkeys: Vec<String>,
    pub free_limit: i32,
    pub remaining_free_emoji: i32,
}

#[derive(Deserialize, Debug, Serialize, Clone)]
pub struct Auth {
    pub access_token: String,
    pub refresh_token: String,
    pub requires_2fa: Option<String>,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct DisplayOrder {
    pub id: Uuid,
    pub user_id: Uuid,
    pub status: OrderStatus,
    pub order_number: String,
    pub order_items: Vec<DisplayOrderItem>,
    pub user: DisplayUser,
    pub total_in_cents: i64,
    pub seconds_until_expiry: Option<u32>,
    pub eligible_for_refund: bool,
    pub misc_refunded_total_in_cents: i64,
    pub refunded_total_in_cents: i64,
}

#[derive(Deserialize, Debug, Serialize)]
pub enum OrderStatus {
    Cancelled,
    Draft,
    Paid,
    PendingPayment,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct DisplayOrderItem {
    pub id: Uuid,
    pub order_id: Uuid,
    pub emoji_id: Option<String>,
    pub item_type: OrderItemTypes,
    pub quantity: i32,
    pub refunded_quantity: i32,
    pub unit_price_in_cents: i32,
    pub company_fee_in_cents: i32,
    pub client_fee_in_cents: i32,
    pub rhythm_score: Option<i32>,
}

#[derive(Deserialize, Debug, Serialize)]
pub enum OrderItemTypes {
    Discount,
    EmojiId,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct ProcessedResult {
    pub auth: Auth,
    pub user: DisplayUser,
    pub yats: Vec<String>,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct ResponseError {
    pub error: String,
    pub fields: HashMap<String, Vec<ErrorItem>>,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct ErrorItem {
    pub code: String,
    pub message: String,
}
