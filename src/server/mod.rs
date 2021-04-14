use crate::cli::keys::CodeKeypair;
use crate::Config;

use actix_web::{error::ErrorInternalServerError, web, App, HttpResponse, HttpServer, Result};
use digest::Digest;
use serde::Deserialize;
use std::collections::HashMap;
use tari_crypto::ristretto::RistrettoPublicKey;
use tari_crypto::ristretto::RistrettoSchnorr;
use tari_crypto::tari_utilities::hex::Hex;
use tari_crypto::{common::Blake256, ristretto::RistrettoSecretKey, signatures::SchnorrSignature};
use tari_crypto::{keys::PublicKey, signatures::SchnorrSignatureError};
use uuid::Uuid;

use api::YatApi;
use error::ServerError;

pub mod api;
mod error;

#[derive(Debug, Deserialize)]
pub struct FreeYatRequest {
    alternate_id: String,
}

#[derive(Clone)]
struct AppState {
    codes: HashMap<Uuid, CodeKeypair>,
    code_ids: Vec<Uuid>,
}

pub type Signature = SchnorrSignature<RistrettoPublicKey, RistrettoSecretKey>;
type SignatureError = SchnorrSignatureError;

/// Sign the hash of the given challenge string with the secret key.
fn sign_challenge(
    secret: RistrettoSecretKey,
    challenge: String,
) -> Result<Signature, SignatureError> {
    let mut rng = rand::thread_rng();
    let (nonce, _) = RistrettoPublicKey::random_keypair(&mut rng);
    let challenge = Blake256::digest(challenge.as_bytes());

    RistrettoSchnorr::sign(secret, nonce, &challenge)
}

async fn sign_code_id_handler(
    data: web::Json<FreeYatRequest>,
    state: web::Data<AppState>,
    code_id: web::Path<Uuid>,
) -> Result<HttpResponse> {
    let keypair = state
        .codes
        .get(&code_id.0)
        .ok_or_else(|| ErrorInternalServerError("Interal state error: No code/keypair."))?;

    let sig = sign_challenge(keypair.secret.clone(), data.alternate_id.clone())
        .map_err(ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(sig))
}

async fn sign_handler(
    data: web::Json<FreeYatRequest>,
    state: web::Data<AppState>,
) -> Result<HttpResponse> {
    // get the default code_id/keypair
    let keypair = state
        .codes
        .get(&Uuid::nil())
        .ok_or_else(|| ErrorInternalServerError("Interal state error: No code/keypair."))?;

    let sig = sign_challenge(keypair.secret.clone(), data.alternate_id.clone())
        .map_err(ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(sig))
}

#[derive(Deserialize)]
struct CreateUserRequest {
    alternate_id: String,
    password: String,
}

async fn user_handler(
    data: web::Json<CreateUserRequest>,
    yat_api: web::Data<YatApi>,
) -> Result<HttpResponse> {
    let user = yat_api
        .user_create(data.alternate_id.clone(), data.password.clone())
        .await
        .map_err(ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(user))
}

async fn process_handler(
    data: web::Json<CreateUserRequest>,
    state: web::Data<AppState>,
    yat_api: web::Data<YatApi>,
) -> Result<HttpResponse> {
    let code_id = state
        .code_ids
        .first()
        .ok_or_else(|| ErrorInternalServerError("No code id found!"))?;

    let keypair = state
        .codes
        .get(code_id)
        .ok_or_else(|| ErrorInternalServerError("Interal state error: No code/keypair."))?;
    let code_pubkey = keypair.pubkey.clone();

    // todo: user already exists flow - this is going to fail if the user exists

    // create user
    let user = yat_api
        .user_create(data.alternate_id.clone(), data.password.clone())
        .await?;
    let user_id = user.id;

    let user_pubkey = user
        .pubkeys
        .first()
        .map(String::as_str)
        .map(RistrettoPublicKey::from_hex)
        .ok_or_else(|| ErrorInternalServerError("No valid user pubkey!"))?
        .map_err(ErrorInternalServerError)?;

    // activate user
    let activation_source = Some("Yat Partner API".to_string());
    let _user = yat_api.user_activate(user_id, activation_source).await?;

    // log in user
    let auth = yat_api
        .user_login(data.alternate_id.clone(), data.password.clone())
        .await?;
    let access_token = auth.access_token;

    // sign request
    let challenge = data.alternate_id.clone();
    let signature =
        sign_challenge(keypair.secret.clone(), challenge).map_err(ErrorInternalServerError)?;

    // random yat
    let _order = yat_api
        .random_yat(
            access_token.clone(),
            *code_id,
            signature,
            code_pubkey.clone(),
        )
        .await?;

    // checkout
    let order = yat_api.checkout(access_token, user_pubkey).await?;

    Ok(HttpResponse::Ok().json(order))
}

pub async fn start_server(config: Config) -> anyhow::Result<(), ServerError> {
    let addr = config.addr;

    HttpServer::new(move || {
        let codes = config.codes.clone();
        let code_ids = config.code_ids.clone();
        let state = AppState { codes, code_ids };

        let api_url = config.api_url.clone();
        let api_key = config.api_key.clone();
        let yat_api = YatApi::new(api_url, api_key);

        App::new()
            .data(state)
            .data(yat_api)
            .route("/sign", web::post().to(sign_handler))
            .route("/sign/{code_id}", web::post().to(sign_code_id_handler))
            .route("/process", web::post().to(process_handler))
            .route("/user", web::post().to(user_handler))
    })
    .bind(addr)?
    .run()
    .await
    .map_err(ServerError::IoError)
}
