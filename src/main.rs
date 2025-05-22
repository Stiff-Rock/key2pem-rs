use ed25519_dalek::SigningKey;
use fern::{
    Dispatch,
    colors::{Color, ColoredLevelConfig},
};
use log::*;
use pkcs8::EncodePrivateKey;
use rsa::{BigUint, pkcs1::EncodeRsaPrivateKey};
use spki::der::zeroize::Zeroizing;
use ssh_key::Algorithm;
use ssh_key::private::PrivateKey;
use std::fs;
use std::path::Path;

/// Convert an SSH key file to OpenSSL PEM format
pub fn convert_ssh_key_to_pem(
    input_path: &Path,
    output_path: &Path,
    _passphrase: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let key_data = fs::read_to_string(input_path)?;

    let private_key = PrivateKey::from_openssh(&key_data)?;

    //TODO: ADD PASSPHRASE LATER
    let pem_content = match &private_key.algorithm() {
        //NOTE: THE HAHS IN HERE MUGHT BE USEFUL TO DETERMINE WHICH to_pkcs TO USE
        Algorithm::Rsa { hash: _ } => {
            debug!("Provided key is RSA");

            let rsa_keypair: &ssh_key::private::RsaKeypair = private_key
                .key_data()
                .rsa()
                .ok_or("Unable to obtain RSA keypair")?;

            let n = BigUint::from_bytes_be(rsa_keypair.public.n.as_bytes());
            let e = BigUint::from_bytes_be(rsa_keypair.public.e.as_bytes());
            let d = BigUint::from_bytes_be(rsa_keypair.private.d.as_bytes());
            let p = BigUint::from_bytes_be(rsa_keypair.private.p.as_bytes());
            let q = BigUint::from_bytes_be(rsa_keypair.private.q.as_bytes());
            let primes: Vec<BigUint> = vec![p, q];

            let rsa_private_key = rsa::RsaPrivateKey::from_components(n, e, d, primes)?;

            rsa_private_key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)?
        }
        //Algorithm::Dsa => {}
        //Algorithm::Ecdsa { .. } => {}
        Algorithm::Ed25519 => {
            debug!("Provided key is Ed25519");

            let ed25519_keypair = private_key
                .key_data()
                .ed25519()
                .ok_or("Unable to obtain Ed25519 keypair")?;

            let private_key_bytes = ed25519_keypair.private.to_bytes();

            let signing_key = SigningKey::from_bytes(&private_key_bytes);

            let pem = signing_key
                .to_pkcs8_pem(pkcs8::LineEnding::LF)
                .map_err(|e| format!("Falied to convert to PEM key - {e}"))?;

            pem
        }
        _ => return Err("Unsupported key algorithm".into()),
    };

    fs::write(output_path, pem_content)?;

    Ok(())
}

fn main() {
    setup_logging();

    let input = Path::new(r"C:\Users\Yago\.ssh\id_ed25519");
    let output = Path::new(r"C:\Users\Yago\.ssh\id_rsa");
    let passphrase = None;

    match convert_ssh_key_to_pem(input, output, passphrase) {
        Ok(_) => debug!("Successfully converted key to PEM format"),
        Err(e) => error!("Error converting key: {}", e),
    }
}

fn setup_logging() {
    let colors = ColoredLevelConfig::new()
        .error(Color::Red)
        .warn(Color::Yellow)
        .info(Color::Green)
        .debug(Color::Blue)
        .trace(Color::Magenta);

    let base_config = fern::Dispatch::new().level(LevelFilter::Trace);
    Dispatch::new()
        .chain(base_config)
        .format(move |out, message, record| {
            out.finish(format_args!(
                "[{}] {}",
                colors.color(record.level()),
                message
            ))
        })
        .chain(std::io::stdout())
        .apply()
        .unwrap();

    info!("Logger initialized");
}
