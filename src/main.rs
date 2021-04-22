mod cli;
mod commands;
mod errors;
mod server;

use crate::cli::codes::attach_pubkey_to_code;
use crate::cli::keys::{generate_keypair, CodeKeypair};
use crate::errors::YatError;
use crate::server::start_server;

use clap::{App as ClapApp, Arg, ArgMatches, SubCommand};
use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::str::FromStr;
use tari_crypto::keys::PublicKey;
use tari_crypto::ristretto::{RistrettoPublicKey, RistrettoSecretKey};
use tari_crypto::tari_utilities::hex::Hex;
use uuid::Uuid;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const LOG_TARGET: &str = "server";

#[derive(Clone, Debug)]
pub struct Config {
    api_url: String,
    api_key: String,
    activation_url: String,
    activation_token: String,
    addr: SocketAddr,
    codes: HashMap<Uuid, CodeKeypair>,
    code_ids: Vec<Uuid>,
}

fn get_config() -> anyhow::Result<Config> {
    dotenv::dotenv().ok();
    let code_ids: Vec<Uuid> = env::var("YAT_CODE_IDS")
        .expect("YAT_CODE_IDS not found")
        .split(',')
        .into_iter()
        .map(Uuid::parse_str)
        .collect::<Result<Vec<Uuid>, _>>()?;

    let yat_secrets: Vec<RistrettoSecretKey> = env::var("YAT_SECRETS")
        .expect("YAT_SECRETS not found")
        .split(',')
        .into_iter()
        .map(RistrettoSecretKey::from_hex)
        .collect::<Result<Vec<RistrettoSecretKey>, _>>()?;

    let api_url = env::var("YAT_API_URL").unwrap_or_else(|_| "https://a.y.at".into());
    let api_key = env::var("YAT_API_KEY").expect("YAT_API_KEY not found");

    let activation_url =
        env::var("YAT_ACTIVATION_URL").unwrap_or_else(|_| "https://activate.y.at".into());
    let activation_token =
        env::var("YAT_ACTIVATION_TOKEN").expect("YAT_ACTIVATION_TOKEN not found");

    let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port = env::var("PORT").unwrap_or_else(|_| "8080".into());

    let addr = SocketAddr::from_str(&format!("{}:{}", host, port))?;

    let mut codes = HashMap::new();
    for (pos, code) in code_ids.iter().enumerate() {
        let secret = yat_secrets
            .get(pos)
            .cloned()
            .ok_or(YatError::MissingSecret)?;

        codes.insert(
            *code,
            CodeKeypair {
                pubkey: RistrettoPublicKey::from_secret_key(&secret),
                secret,
            },
        );
    }

    // also store the first/default code with the nil Uuid
    let secret = yat_secrets.get(0).cloned().ok_or(YatError::MissingSecret)?;
    codes.insert(
        Uuid::nil(),
        CodeKeypair {
            pubkey: RistrettoPublicKey::from_secret_key(&secret),
            secret,
        },
    );

    Ok(Config {
        api_url,
        api_key,
        activation_url,
        activation_token,
        addr,
        codes,
        code_ids,
    })
}

fn get_matches() -> ArgMatches<'static> {
    ClapApp::new("Yat Partner")
        .version(VERSION)
        .author("Yat Labs")
        .about("Signs requests for generating a free random Yat for our partners")
        .subcommand(
            SubCommand::with_name("codes")
                .about("Manage codes")
                .arg(
                    Arg::with_name("attach")
                        .short("a")
                        .long("attach")
                        .requires_all(&["pubkey", "code_id"])
                        .help("Attach a public key to a code id."),
                )
                .arg(
                    Arg::with_name("pubkey")
                        .short("p")
                        .long("pubkey")
                        .value_name("PUBKEY")
                        .help("The hex public key.")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("code_id")
                        .short("c")
                        .long("code-id")
                        .value_name("CODE_ID")
                        .help("The code id.")
                        .takes_value(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("keys").about("Manage key pairs").arg(
                Arg::with_name("generate")
                    .short("g")
                    .long("generate")
                    .help("Generate a new key pair."),
            ),
        )
        .get_matches()
}

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let config = get_config()?;
    let matches = get_matches();

    if let Some(matches) = matches.subcommand_matches("keys") {
        if matches.is_present("generate") {
            println!("Generate key pair");
            println!("{}", generate_keypair());
        }
    } else if let Some(matches) = matches.subcommand_matches("codes") {
        if matches.is_present("attach") {
            let pubkey_hex = matches.value_of("pubkey").expect("Missing pubkey [-p]");
            let code_id =
                Uuid::from_str(matches.value_of("code_id").expect("Missing code_id [-c]")).unwrap();
            attach_pubkey_to_code(pubkey_hex.to_string(), code_id, &config)
                .await
                .unwrap();
        }
    } else {
        log::info!(target: LOG_TARGET, "Server starting at {}", config.addr);
        start_server(config).await?;
    }

    Ok(())
}
