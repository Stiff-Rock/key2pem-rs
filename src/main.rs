use std::{
    fs::{create_dir_all, remove_dir_all},
    path::Path,
};

use auth_git2_pem::GitAuthenticator;
use dirs::home_dir;
use fern::{
    Dispatch,
    colors::{Color, ColoredLevelConfig},
};
use log::{LevelFilter, info};

fn main() {
    setup_logging();

    let home = home_dir().expect("Error getting home directory");
    let into = home.join("Desktop").join("PrivateRepo");

    if !into.exists() {
        panic!("Target dir <{}> doesn't exist", into.display());
    }

    clear_directory(&into);

    let ssh_clone_url = "git@github.com:Stiff-Rock/JavaFx.git";

    // IMPLEMENT UI PROMPTER
    let auth = GitAuthenticator::new();

    let res = auth.clone_repo(ssh_clone_url, &into);

    match res {
        Ok(_) => println!("Successfully cloned repository"),
        Err(error) => eprintln!("Error cloning repository: {}", error),
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

fn clear_directory(path: &Path) {
    if path.exists() {
        remove_dir_all(&path).expect("Error removing target directory");
    }

    create_dir_all(&path).expect("Error creating target directory");
}
