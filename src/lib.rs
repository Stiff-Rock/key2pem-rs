use ed25519_dalek::SigningKey;
use log::debug;
use p256::SecretKey as P256SecretKey;
use p384::SecretKey as P384SecretKey;
use p521::SecretKey as P521SecretKey;
use pkcs8::EncodePrivateKey;
use rsa::{BigUint, pkcs1::EncodeRsaPrivateKey};
use ssh_key::private::PrivateKey;
use ssh_key::{Algorithm, EcdsaCurve};
use std::fs;
use std::path::Path;

/// Convert an SSH key file to OpenSSL PEM format
/// Note: Ed25519 convertion results in a non-valid key, Ecdsa convertion works with ssh connection
/// with github but not through git2's libssh2-rs library and DSA is no longer supported by GitHub
pub fn convert_ssh_key_to_pem(
    input_path: &Path,
    output_path: &Path,
    passphrase: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    debug!("Attepmting convertion of key at {:#?}", input_path);

    let key_data = fs::read_to_string(input_path)?;

    let private_key = PrivateKey::from_openssh(&key_data)?;

    //TODO: ADD PASSPHRASE LATER
    let pem_content = match &private_key.algorithm() {
        //NOTE: THE HAHS IN HERE MUGHT BE USEFUL TO DETERMINE WHICH to_pkcs TO USE
        Algorithm::Rsa { hash } => {
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
        Algorithm::Ed25519 => {
            debug!("Provided key is Ed25519");

            let ed25519_keypair = private_key
                .key_data()
                .ed25519()
                .ok_or("Unable to obtain Ed25519 keypair")?;

            let private_key_bytes = ed25519_keypair.private.to_bytes();

            let signing_key = SigningKey::from_bytes(&private_key_bytes);

            signing_key
                .to_pkcs8_pem(pkcs8::LineEnding::LF)
                .map_err(|e| format!("Falied to convert private key to PKCS8 PEM - {e}"))?
        }
        Algorithm::Ecdsa { curve } => {
            debug!("Provided key is Ecdsa");

            let ecdsa_keypair = private_key
                .key_data()
                .ecdsa()
                .ok_or("Unable to obtain ECDSA keypair")?;

            let private_key_bytes = ecdsa_keypair.private_key_bytes();

            match curve {
                EcdsaCurve::NistP256 => {
                    let sk = P256SecretKey::from_slice(private_key_bytes)?;
                    sk.to_sec1_pem(pkcs8::LineEnding::LF)?
                }
                EcdsaCurve::NistP384 => {
                    let sk = P384SecretKey::from_slice(private_key_bytes)?;
                    sk.to_sec1_pem(pkcs8::LineEnding::LF)?
                }
                EcdsaCurve::NistP521 => {
                    let sk = P521SecretKey::from_slice(private_key_bytes)?;
                    sk.to_sec1_pem(pkcs8::LineEnding::LF)?
                }
            }
        }
        _ => return Err("Unsupported key algorithm".into()),
    };

    fs::write(output_path, pem_content)?;

    Ok(())
}
