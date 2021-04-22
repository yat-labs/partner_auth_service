use crate::Config;
use tari_crypto::ristretto::RistrettoPublicKey;
use tari_crypto::tari_utilities::hex::Hex;
use uuid::Uuid;

pub async fn attach_pubkey_to_code(
    pubkey_hex: String,
    code_id: Uuid,
    config: &Config,
) -> std::io::Result<()> {
    match RistrettoPublicKey::from_hex(&pubkey_hex) {
        Ok(p) => {
            let client = actix_web::client::Client::new();
            match client
                .post(format!(
                    "{}/codes/{code_id}/pubkeys/{pubkey}",
                    config.api_url,
                    code_id = code_id,
                    pubkey = p.to_hex()
                ))
                .header("X-Api-Key", config.api_key.clone())
                .send()
                .await
            {
                Ok(resp) => {
                    eprintln!("resp.status() = {:?}", resp);
                }

                Err(e) => {
                    eprintln!("e = {:?}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("Invalid pubkey = {:?}", e);
        }
    }
    Ok(())
}
