pub mod cli;
mod defaults;
mod error;
mod hardware;
mod io;
mod logger;
mod pki;

pub mod commands {
    pub mod get_ca;
    pub mod init_ca;
    pub mod issue_host;
    pub mod list_keys;
    pub mod list_slots;
    pub mod sign_csr;
}

pub use error::AppError;

pub fn run() -> i32 {
    let cli = cli::parse();
    logger::init(cli.log, cli::has_explicit_log_flag());

    match cli::run(cli) {
        Ok(()) => 0,
        Err(err) => {
            tracing::error!(error = %err, "command failed");
            1
        }
    }
}
