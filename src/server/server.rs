use crate::cli::keys::CodeKeypair;
use crate::Config;
use actix_web::{web, App, HttpResponse, HttpServer, Result};
use digest::Digest;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tari_crypto::common::Blake256;
use tari_crypto::ristretto::RistrettoSchnorr;
use tari_crypto::tari_utilities::hex::Hex;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct FreeYatRequest {
    alternate_id: String,
}

struct AppState {
    codes: HashMap<Uuid, CodeKeypair>,
}

#[derive(Serialize, Deserialize)]
pub struct SignResult {
    pub public_nonce: Option<String>,
    pub signature: Option<String>,
    pub error: String,
}

impl Default for SignResult {
    fn default() -> Self {
        SignResult {
            public_nonce: None,
            signature: None,
            error: "".into(),
        }
    }
}

async fn sign_request(
    data: web::Json<FreeYatRequest>,
    state: web::Data<AppState>,
    code_id: web::Path<Uuid>,
) -> Result<HttpResponse> {
    let keypair = state.codes.get(&code_id.0).unwrap();
    let mut result: SignResult = SignResult::default();
    match RistrettoSchnorr::sign(
        keypair.secret.clone(),
        keypair.secret.clone(),
        Blake256::digest(data.alternate_id.as_bytes()).as_slice(),
    ) {
        Ok(sig) => {
            result.public_nonce = Some(keypair.pubkey.to_hex());
            result.signature = Some(sig.get_signature().to_hex());
        }
        Err(e) => {
            result.error = format!("Could not create signature. {}", e.to_string());
        }
    };

    Ok(HttpResponse::Ok().json(&result))
}

pub async fn start_server(config: &Config) -> std::io::Result<()> {
    let addr = config.addr.clone();
    let config = config.clone();
    HttpServer::new(move || {
        App::new()
            .route("/sign/{code_id}", web::post().to(sign_request))
            .data(AppState {
                codes: config.codes.clone(),
            })
    })
    .bind(addr)?
    .run()
    .await
}
