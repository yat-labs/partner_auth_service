use actix_web::{
    client::JsonPayloadError,
    error::{ErrorInternalServerError, PayloadError},
};
use tari_crypto::tari_utilities::hex::HexError;
use thiserror::Error;
use http::StatusCode;

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),
}

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Send Request Error: {0}")]
    SendRequestError(String),
    #[error("HTTP Error: {0}")]
    HttpError(String),
    #[error("JsonPayload Error: {0}")]
    JsonPayloadError(#[from] JsonPayloadError),
    #[error("Payload Error: {0}")]
    PayloadError(#[from] PayloadError),
    #[error("Hex Error: {0}")]
    HexError(#[from] HexError),
}

impl From<ApiError> for actix_web::error::Error {
    fn from(err: ApiError) -> Self {
        // todo better errors
        ErrorInternalServerError(err)
    }
}
