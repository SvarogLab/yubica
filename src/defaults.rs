use crate::cli::{CliAlgorithm, CliPinPolicy, CliTouchPolicy, LogLevel};
use x509_cert::ext::pkix::{KeyUsage, KeyUsages, constraints::BasicConstraints};
use yubikey::piv::SlotId;

pub struct LoggingDefaults;
pub struct CaDefaults;
pub struct SlotsDefaults;
pub struct GetCaDefaults;
pub struct IoDefaults;
pub struct HostDefaults;
pub struct CrlDefaults;

impl LoggingDefaults {
    pub const fn level() -> LogLevel {
        LogLevel::Info
    }
}

impl CaDefaults {
    pub const SUBJECT: &str = "CN=Offline Root CA";
    pub const VALID_YEARS: u16 = 20;
    pub const SLOT: &str = "9c";

    pub const fn algorithm() -> CliAlgorithm {
        CliAlgorithm::EccP384
    }

    pub const fn pin_policy() -> CliPinPolicy {
        CliPinPolicy::Always
    }

    pub const fn touch_policy() -> CliTouchPolicy {
        CliTouchPolicy::Always
    }

    pub fn key_usage() -> KeyUsage {
        KeyUsage::from(KeyUsages::KeyCertSign | KeyUsages::CRLSign)
    }

    pub const fn basic_constraints() -> BasicConstraints {
        BasicConstraints {
            ca: true,
            path_len_constraint: None,
        }
    }
}

impl SlotsDefaults {
    pub const SLOTS: [SlotId; 5] = [
        SlotId::Authentication,
        SlotId::Signature,
        SlotId::KeyManagement,
        SlotId::CardAuthentication,
        SlotId::Attestation,
    ];
}

impl GetCaDefaults {
    pub const SLOT: &str = CaDefaults::SLOT;
    pub const FILENAME: &str = "current-ca";
}

pub struct CsrDefaults;

impl CsrDefaults {
    pub const SLOT: &str = CaDefaults::SLOT;
    pub const VALID_YEARS: u16 = CaDefaults::VALID_YEARS;
    pub const FILENAME: &str = "issued-certificate";
}

impl CrlDefaults {
    pub const SLOT: &str = CaDefaults::SLOT;
    pub const NEXT_UPDATE_DAYS: u32 = 30;
    pub const FILENAME: &str = "revoked";
}

impl IoDefaults {
    pub const PATH: &str = ".";
}

impl HostDefaults {
    pub const VALID_YEARS: u16 = 1;
    pub const FILENAME: &str = "tls";

    pub const fn algorithm() -> CliAlgorithm {
        CliAlgorithm::EccP384
    }

    pub fn key_usage() -> KeyUsage {
        // Tuple-struct construction (not `KeyUsage::from(..)`) pins the `.into()`
        // target type to the `FlagSet` field directly, avoiding ambiguity with
        // `KeyUsages`'s blanket `From<T> for T` impl.
        KeyUsage(KeyUsages::DigitalSignature.into())
    }

    pub const fn basic_constraints() -> BasicConstraints {
        BasicConstraints {
            ca: false,
            path_len_constraint: None,
        }
    }
}
