use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use std::str::FromStr;
use yubikey::{
    PinPolicy, TouchPolicy,
    piv::{AlgorithmId, SlotId},
};

use crate::{
    commands::{get_ca, init_ca, issue_host, list_keys, list_slots, sign_csr},
    defaults::{CaDefaults, CsrDefaults, GetCaDefaults, HostDefaults, IoDefaults, LoggingDefaults},
    error::AppError,
};

/// Help text shared by every subcommand's `--serial`: it's the one argument
/// that's mandatory everywhere except `list-keys`, whose entire purpose is to
/// discover it in the first place.
const SERIAL_HELP: &str = "Serial number of the YubiKey to operate on (see `list-keys`)";

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    name = "yubica",
    about = "Manage an offline root CA on a YubiKey PIV slot and sign certificates/CSRs without exposing the root private key"
)]
pub struct Cli {
    #[arg(
        long,
        value_enum,
        default_value_t = LoggingDefaults::level(),
        global = true,
        help = "Log verbosity; overrides RUST_LOG when given"
    )]
    pub log: LogLevel,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    ListKeys(ListKeysArgs),
    ListSlots(ListSlotsArgs),
    InitCa(InitCaArgs),
    GetCa(GetCaArgs),
    SignCsr(SignCsrArgs),
    IssueHost(IssueHostArgs),
}

// Shared by every command that accepts a certificate validity window: at
// most one of the three is allowed, and each name conflicts with the other
// two identically, so this is defined once and flattened everywhere. A doc
// comment is deliberately not used here: clap derive would surface it as the
// `--help` header of whichever subcommand flattens this struct.
#[derive(Debug, Args)]
pub struct ValidityArgs {
    #[arg(
        long,
        conflicts_with_all = ["valid_months", "valid_days"],
        help = "Certificate validity in whole years (mutually exclusive with --valid-months/--valid-days)"
    )]
    pub valid_years: Option<u16>,
    #[arg(
        long,
        conflicts_with_all = ["valid_years", "valid_days"],
        help = "Certificate validity in whole months (mutually exclusive with --valid-years/--valid-days)"
    )]
    pub valid_months: Option<u16>,
    #[arg(
        long,
        conflicts_with_all = ["valid_years", "valid_months"],
        help = "Certificate validity in whole days (mutually exclusive with --valid-years/--valid-months)"
    )]
    pub valid_days: Option<u32>,
}

// Shared by every command that verifies a PIN against the YubiKey before
// using it, so the `--pin`/`YUBICA_PIN` wiring is defined once. See the note
// on `ValidityArgs` about why this isn't a doc comment.
#[derive(Debug, Args)]
pub struct PinArg {
    #[arg(
        long,
        env = "YUBICA_PIN",
        hide_env_values = true,
        help = "YubiKey PIN, verified before use"
    )]
    pub pin: Option<String>,
}

/// Enumerate connected PC/SC readers and report the serial of any YubiKey
/// found. The only command that doesn't require `--serial`.
#[derive(Debug, Args)]
pub struct ListKeysArgs {}

/// Log the occupancy state (present/absent) of every common PIV slot.
#[derive(Debug, Args)]
pub struct ListSlotsArgs {
    #[arg(long, env = "YUBICA_SERIAL", help = SERIAL_HELP)]
    pub serial: u32,
}

/// Read the certificate from a PIV slot and export it, if present.
#[derive(Debug, Args)]
pub struct GetCaArgs {
    #[arg(long, env = "YUBICA_SERIAL", help = SERIAL_HELP)]
    pub serial: u32,
    #[arg(
        long,
        default_value = GetCaDefaults::SLOT,
        value_parser = parse_slot,
        help = "PIV slot to read"
    )]
    pub slot: SlotId,
    #[arg(
        long,
        default_value = IoDefaults::PATH,
        help = "Directory to write the exported certificate into (must already exist)"
    )]
    pub iopath: PathBuf,
    #[arg(
        long,
        default_value = GetCaDefaults::FILENAME,
        help = "Base filename for the exported certificate (produces <filename>.crt)"
    )]
    pub filename: String,
}

/// Create a self-signed root CA certificate backed by a private key
/// generated inside the YubiKey. Does not write any files; use `get-ca`
/// to export the resulting certificate.
#[derive(Debug, Args)]
pub struct InitCaArgs {
    #[arg(long, env = "YUBICA_SERIAL", help = SERIAL_HELP)]
    pub serial: u32,
    #[arg(
        long,
        default_value = CaDefaults::SUBJECT,
        help = "Subject (DN) for the root CA certificate"
    )]
    pub subject: String,
    #[command(flatten)]
    pub validity: ValidityArgs,
    #[arg(
        long,
        value_enum,
        default_value_t = CaDefaults::algorithm(),
        help = "Key algorithm for the generated root CA key"
    )]
    pub algorithm: CliAlgorithm,
    #[arg(
        long,
        value_enum,
        default_value_t = CaDefaults::pin_policy(),
        help = "PIV PIN policy for the generated key"
    )]
    pub pin_policy: CliPinPolicy,
    #[arg(
        long,
        value_enum,
        default_value_t = CaDefaults::touch_policy(),
        help = "PIV touch policy for the generated key"
    )]
    pub touch_policy: CliTouchPolicy,
    #[arg(
        long,
        default_value = CaDefaults::SLOT,
        value_parser = parse_slot,
        help = "PIV slot to initialize"
    )]
    pub slot: SlotId,
    #[arg(
        long,
        env = "YUBICA_MGM_KEY_HEX",
        hide_env_values = true,
        help = "YubiKey management key in hex (defaults to the factory key if omitted; a non-default key is required)"
    )]
    pub mgm_key_hex: Option<String>,
    #[command(flatten)]
    pub pin: PinArg,
    #[arg(
        long,
        help = "Skip the slot-occupancy preflight check (does not delete existing keys/certs)"
    )]
    pub force: bool,
}

/// Sign an existing CSR with the CA certificate/key from a YubiKey PIV slot.
/// Reads the CSR from `<iopath>/<filename>.csr` (PEM or DER).
#[derive(Debug, Args)]
pub struct SignCsrArgs {
    #[arg(long, env = "YUBICA_SERIAL", help = SERIAL_HELP)]
    pub serial: u32,
    #[arg(
        long,
        default_value = CsrDefaults::SLOT,
        value_parser = parse_slot,
        help = "PIV slot holding the CA certificate/key to sign with"
    )]
    pub slot: SlotId,
    #[command(flatten)]
    pub validity: ValidityArgs,
    #[command(flatten)]
    pub pin: PinArg,
    #[arg(
        long,
        help = "Sign as an intermediate CA: forces BasicConstraints CA:TRUE and KeyUsage keyCertSign+cRLSign, overriding whatever the CSR itself requested for those two extensions (whether something is a CA is the signer's decision, not the requester's)"
    )]
    pub ca: bool,
    #[arg(
        long,
        default_value = IoDefaults::PATH,
        help = "Directory holding the input CSR and to write the signed certificate into (must already exist)"
    )]
    pub iopath: PathBuf,
    #[arg(
        long,
        default_value = CsrDefaults::FILENAME,
        help = "Base filename shared by the input CSR (<filename>.csr) and the signed certificate (<filename>.crt)"
    )]
    pub filename: String,
}

/// Generate a host private key and CSR locally, then sign it with the
/// YubiKey-backed CA.
#[derive(Debug, Args)]
pub struct IssueHostArgs {
    #[arg(long, env = "YUBICA_SERIAL", help = SERIAL_HELP)]
    pub serial: u32,
    #[arg(
        long,
        required = true,
        num_args = 1..,
        help = "Hostname or IP to include in the certificate SAN (repeatable)"
    )]
    pub host: Vec<String>,
    #[arg(
        long,
        help = "Subject (DN) for the host certificate (defaults to CN=<first --host>)"
    )]
    pub subject: Option<String>,
    #[command(flatten)]
    pub validity: ValidityArgs,
    #[arg(
        long,
        value_enum,
        default_value_t = HostDefaults::algorithm(),
        help = "Key algorithm for the generated host private key"
    )]
    pub algorithm: CliAlgorithm,
    #[arg(
        long,
        default_value = CsrDefaults::SLOT,
        value_parser = parse_slot,
        help = "PIV slot holding the CA certificate/key to sign with"
    )]
    pub slot: SlotId,
    #[command(flatten)]
    pub pin: PinArg,
    #[arg(
        long,
        env = "YUBICA_PASSWD",
        hide_env_values = true,
        help = "Password to encrypt the generated private key with (PKCS#8)"
    )]
    pub passwd: Option<String>,
    #[arg(
        long,
        default_value = IoDefaults::PATH,
        help = "Directory to write the host key/CSR/certificate into (must already exist)"
    )]
    pub iopath: PathBuf,
    #[arg(
        long,
        default_value = HostDefaults::FILENAME,
        help = "Base filename for the generated artifacts (produces <filename>.key/.csr/.crt)"
    )]
    pub filename: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum CliAlgorithm {
    EccP256,
    EccP384,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum CliPinPolicy {
    Default,
    Never,
    Once,
    Always,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum CliTouchPolicy {
    Default,
    Never,
    Always,
    Cached,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

pub fn parse() -> Cli {
    Cli::parse()
}

pub fn has_explicit_log_flag() -> bool {
    std::env::args_os().any(|arg| {
        let arg = arg.to_string_lossy();
        arg == "--log" || arg.starts_with("--log=")
    })
}

pub fn run(cli: Cli) -> Result<(), AppError> {
    match cli.command {
        Command::ListKeys(args) => list_keys::run(&args),
        Command::ListSlots(args) => list_slots::run(&args),
        Command::InitCa(args) => init_ca::run(&args),
        Command::GetCa(args) => get_ca::run(&args),
        Command::SignCsr(args) => sign_csr::run(&args),
        Command::IssueHost(args) => issue_host::run(&args),
    }
}

fn parse_slot(value: &str) -> Result<SlotId, String> {
    SlotId::from_str(value).map_err(|err| format!("invalid slot '{value}': {err:?}"))
}

impl From<CliAlgorithm> for AlgorithmId {
    fn from(value: CliAlgorithm) -> Self {
        match value {
            CliAlgorithm::EccP256 => AlgorithmId::EccP256,
            CliAlgorithm::EccP384 => AlgorithmId::EccP384,
        }
    }
}

impl From<CliPinPolicy> for PinPolicy {
    fn from(value: CliPinPolicy) -> Self {
        match value {
            CliPinPolicy::Default => PinPolicy::Default,
            CliPinPolicy::Never => PinPolicy::Never,
            CliPinPolicy::Once => PinPolicy::Once,
            CliPinPolicy::Always => PinPolicy::Always,
        }
    }
}

impl From<CliTouchPolicy> for TouchPolicy {
    fn from(value: CliTouchPolicy) -> Self {
        match value {
            CliTouchPolicy::Default => TouchPolicy::Default,
            CliTouchPolicy::Never => TouchPolicy::Never,
            CliTouchPolicy::Always => TouchPolicy::Always,
            CliTouchPolicy::Cached => TouchPolicy::Cached,
        }
    }
}

impl LogLevel {
    pub const fn as_filter(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}
