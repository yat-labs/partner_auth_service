use rand::rngs::OsRng;
use std::fmt::{Display, Formatter};
use tari_crypto::keys::PublicKey;
use tari_crypto::ristretto::{RistrettoPublicKey, RistrettoSecretKey};
use tari_crypto::tari_utilities::hex::Hex;

#[derive(Clone, Debug)]
pub struct CodeKeypair {
    pub pubkey: RistrettoPublicKey,
    pub secret: RistrettoSecretKey,
}

pub fn generate_keypair() -> CodeKeypair {
    let (secret, pubkey) = RistrettoPublicKey::random_keypair(&mut OsRng);
    CodeKeypair { secret, pubkey }
}

impl Display for CodeKeypair {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Secret Key: {}\nPublic Key: {}\n",
            self.secret.to_hex(),
            self.pubkey.to_hex()
        )
    }
}
