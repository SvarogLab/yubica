use thiserror::Error;
use yubikey::piv::SlotId;

#[derive(Debug, Error)]
pub enum AppError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    YubiKey(#[from] yubikey::Error),
    #[error(transparent)]
    Der(#[from] x509_cert::der::Error),
    #[error(transparent)]
    Builder(#[from] x509_cert::builder::Error),
    #[error(transparent)]
    Pkcs8(#[from] pkcs8::Error),
    #[error(transparent)]
    Signature(#[from] signature::Error),
    #[error(transparent)]
    Spki(#[from] x509_cert::spki::Error),
    #[error("invalid subject: {0}")]
    InvalidSubject(String),
    #[error("invalid management key hex: {0}")]
    InvalidManagementKeyHex(String),
    #[error("invalid io path: {0}")]
    InvalidIoPath(String),
    #[error(
        "init-ca requires --pin so the current YubiKey PIN can be verified before key generation"
    )]
    PinRequiredForCaInitialization,
    #[error(
        "refusing to initialize a CA while using the factory default YubiKey management key; set a non-default management key and pass it with --mgm-key-hex"
    )]
    FactoryDefaultManagementKey,
    #[error(
        "refusing to initialize a CA with the factory default YubiKey PIN; change the token PIN first"
    )]
    FactoryDefaultPin,
    #[error("failed to compute validity window for {0} calendar years")]
    InvalidValidityYears(u16),
    #[error("failed to compute validity window for {0} calendar months")]
    InvalidValidityMonths(u16),
    #[error("password-based encryption is not supported for {0}")]
    UnsupportedPasswordEncryption(&'static str),
    #[error("slot {slot} already contains a key or certificate; rerun with --force to replace it")]
    SlotOccupied { slot: SlotId },
    #[error("failed to parse csr: {0}")]
    InvalidCsr(String),
    #[error(
        "csr requests CA capabilities (BasicConstraints CA:TRUE or KeyUsage keyCertSign/cRLSign) but --ca was not passed; pass --ca to sign it as an intermediate CA, or resubmit a CSR without those extensions"
    )]
    CsrRequestsCaWithoutCaFlag,
    #[error("invalid revoked-certificate list: {0}")]
    InvalidCrlInput(String),
}
