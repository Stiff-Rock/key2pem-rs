use fern::{
    Dispatch,
    colors::{Color, ColoredLevelConfig},
};
use key2pem::convert_ssh_key_to_pem;
use log::{LevelFilter, debug, error, info};
use std::path::Path;

fn main() {
    setup_logging();

    let input = Path::new(r"C:\Users\Yago\.ssh\id_rsa");
    let output = Path::new(r"C:\Users\Yago\.ssh\id_rsa_pem");

    match convert_ssh_key_to_pem(input, output) {
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
