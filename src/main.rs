fn main() {
    setup_logging();

    let input = Path::new(r"C:\Users\yago.pernas\.ssh\id_rsa");
    let output = Path::new(r"C:\Users\yago.pernas\.ssh\id_rsa_pem");
    let passphrase = None;

    match convert_ssh_key_to_pem(input, output, passphrase) {
        Ok(_) => debug!("Successfully converted key to PEM format"),
        Err(e) => error!("Error converting key: {}", e),
    }
}
