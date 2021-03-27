use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder, Result};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tari_crypto::keys::PublicKey;
use tari_crypto::ristretto::{RistrettoPublicKey, RistrettoSecretKey};
#[derive(Deserialize)]
pub struct FreeYatRequest {
    username: String,
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

async fn sign_request(data: web::Json<FreeYatRequest>) -> Result<HttpResponse> {
    let mut result: SignResult = SignResult::default();

    Ok(HttpResponse::Ok().json(&result))
}

struct AppState {
    app_name: String,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    eprintln!(
        "RistrettoPublicKey::random_keypair(&mut OsRng) = {:?}",
        RistrettoPublicKey::random_keypair(&mut OsRng)
    );
    HttpServer::new(|| {
        App::new().route("/sign", web::post().to(sign_request))
        // .data(AppState {
        //     app_name: String::from("Yat"),
        // })
        // .service(web::scope("/code").route("/hey", web::get().to(manual_hello)))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
