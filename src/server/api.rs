use super::{error::ApiError, Signature};

use actix_web::client::Client;
use http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use tari_crypto::ristretto::RistrettoPublicKey;
use tari_crypto::tari_utilities::hex::Hex;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct YatApi {
    api_url: String,
    api_key: String,
}

impl YatApi {
    pub fn new(api_url: String, api_key: String) -> Self {
        YatApi { api_url, api_key }
    }

    /// Register a new user
    pub async fn user_create(
        &self,
        alternate_id: String,
        password: String,
    ) -> Result<DisplayUser, ApiError> {
        let client = Client::default();
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
        let client = Client::default();
        let json = json!({
            "activation_source": activation_source,
        });

        let mut response = client
            .patch(format!("{}/users/{}/activate", self.api_url, user_id))
            .header("X-Api-Key", self.api_key.as_str())
            .send_json(&json)
            .await
            .map_err(|e| ApiError::SendRequestError(e.to_string()))?;

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
        let client = Client::default();
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
            status => return Err(ApiError::HttpError(status.to_string())),
        };

        Ok(auth)
    }

    /// Request a random Yat for the user
    pub async fn random_yat(
        &self,
        access_token: String,
        code_id: Uuid,
        signature: Signature,
        pubkey: RistrettoPublicKey,
    ) -> Result<DisplayOrder, ApiError> {
        let client = Client::default();
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
            .map_err(|e| ApiError::SendRequestError(e.to_string()))?;

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
        let client = Client::default();
        let json = json!({
            "method": "Free",
            "payment_method_id": "ec18d2d7-d2e0-41e4-98e4-847f14422d8a",
            "provider": "Free",
            "pubkey": pubkey.to_hex(),
            "save_payment_method": true,
            "set_default": true,
            "token": "string",
            "tracking_data": {},
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

#[derive(Deserialize, Debug, Serialize)]
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
pub struct ResponseError {
    pub error: String,
    pub fields: HashMap<String, Vec<ErrorItem>>,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct ErrorItem {
    pub code: String,
    pub message: String,
}
