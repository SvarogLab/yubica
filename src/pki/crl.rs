use std::{
    fs,
    path::Path,
    time::{Duration, SystemTime},
};

use x509_cert::{
    Version,
    crl::{CertificateList, RevokedCert, TbsCertList},
    der::{DateTime, Encode, asn1::Uint},
    ext::{
        AsExtension,
        pkix::{
            AuthorityKeyIdentifier,
            crl::{CrlNumber, CrlReason},
        },
    },
    serial_number::SerialNumber,
    spki::{DynSignatureAlgorithmIdentifier, SignatureBitStringEncoding},
    time::Time,
};
use yubikey::{
    YubiKey,
    certificate::{
        Certificate,
        yubikey_signer::{KeyType, Signer},
    },
    piv::SlotId,
};

use crate::{
    cli::CliAlgorithm,
    error::AppError,
    pki::{algorithm::detect_algorithm, validity::time_from_date_time},
};

/// One entry to include in a generated CRL: the serial number of the
/// revoked certificate, when it was revoked, and (optionally) why.
pub struct RevokedEntry {
    pub serial: SerialNumber,
    pub revocation_date: Time,
    pub reason: Option<CrlReason>,
}

/// Parses a file listing revoked certificates, one `serial[,date[,reason]]`
/// entry per line. Blank lines and lines starting with `#` are ignored.
/// `serial` is hex (`:`/space separators allowed); `date` is `YYYY-MM-DD` and
/// defaults to now if omitted; `reason` is a kebab-case RFC 5280 CRLReason
/// name (e.g. `key-compromise`) and is omitted from the entry if absent.
pub fn parse_revoked_file(path: &Path) -> Result<Vec<RevokedEntry>, AppError> {
    let content = fs::read_to_string(path)?;
    let mut entries = Vec::new();

    for (line_number, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let entry = parse_revoked_line(line)
            .map_err(|err| AppError::InvalidCrlInput(format!("line {}: {err}", line_number + 1)))?;
        entries.push(entry);
    }

    Ok(entries)
}

fn parse_revoked_line(line: &str) -> Result<RevokedEntry, String> {
    let mut fields = line.splitn(3, ',').map(str::trim);
    let serial = fields
        .next()
        .filter(|field| !field.is_empty())
        .ok_or_else(|| "missing serial".to_string())
        .and_then(parse_serial)?;
    let revocation_date = match fields.next().filter(|field| !field.is_empty()) {
        Some(date) => parse_date(date)?,
        None => Time::try_from(SystemTime::now()).map_err(|err| err.to_string())?,
    };
    let reason = fields
        .next()
        .filter(|field| !field.is_empty())
        .map(parse_reason)
        .transpose()?;

    Ok(RevokedEntry {
        serial,
        revocation_date,
        reason,
    })
}

fn parse_serial(field: &str) -> Result<SerialNumber, String> {
    // Same separator set as `parse_management_key` (hardware/management.rs),
    // so both hex-input flags accept the same formats.
    let normalized: String = field
        .chars()
        .filter(|ch| !matches!(ch, ':' | '-' | ' '))
        .collect();
    let bytes =
        hex::decode(&normalized).map_err(|err| format!("invalid serial hex '{field}': {err}"))?;
    SerialNumber::new(&bytes).map_err(|err| format!("invalid serial '{field}': {err}"))
}

fn parse_date(field: &str) -> Result<Time, String> {
    let mut parts = field.splitn(3, '-');
    let (year, month, day) = match (parts.next(), parts.next(), parts.next()) {
        (Some(year), Some(month), Some(day)) => (year, month, day),
        _ => return Err(format!("expected date as YYYY-MM-DD, got '{field}'")),
    };
    let year: u16 = year
        .parse()
        .map_err(|_| format!("invalid year in date '{field}'"))?;
    let month: u8 = month
        .parse()
        .map_err(|_| format!("invalid month in date '{field}'"))?;
    let day: u8 = day
        .parse()
        .map_err(|_| format!("invalid day in date '{field}'"))?;

    let date_time = DateTime::new(year, month, day, 0, 0, 0)
        .map_err(|err| format!("invalid date '{field}': {err:?}"))?;
    time_from_date_time(date_time).map_err(|err| err.to_string())
}

fn parse_reason(field: &str) -> Result<CrlReason, String> {
    match field.to_ascii_lowercase().as_str() {
        "unspecified" => Ok(CrlReason::Unspecified),
        "key-compromise" => Ok(CrlReason::KeyCompromise),
        "ca-compromise" => Ok(CrlReason::CaCompromise),
        "affiliation-changed" => Ok(CrlReason::AffiliationChanged),
        "superseded" => Ok(CrlReason::Superseded),
        "cessation-of-operation" => Ok(CrlReason::CessationOfOperation),
        "certificate-hold" => Ok(CrlReason::CertificateHold),
        "remove-from-crl" => Ok(CrlReason::RemoveFromCRL),
        "privilege-withdrawn" => Ok(CrlReason::PrivilegeWithdrawn),
        "aa-compromise" => Ok(CrlReason::AaCompromise),
        other => Err(format!("unknown revocation reason '{other}'")),
    }
}

/// Computes `nextUpdate` as `next_update_days` from now, as the X.509 time the
/// CRL carries. Either limit can be hit first - `SystemTime`'s range differs by
/// platform (Windows ends in the year 30828, Linux far beyond), while X.509's
/// GeneralizedTime ends in 9999 - so both are checked here, and an accidentally
/// huge `--next-update-days` is the same error everywhere instead of a panic.
fn checked_next_update(next_update_days: u32) -> Result<Time, AppError> {
    let duration = Duration::from_secs(u64::from(next_update_days) * 24 * 60 * 60);
    SystemTime::now()
        .checked_add(duration)
        .and_then(|at| Time::try_from(at).ok())
        .ok_or_else(|| {
            AppError::InvalidCrlInput(format!(
                "--next-update-days {next_update_days} is too large to represent"
            ))
        })
}

/// Builds a CRL listing `revoked` and signs it with the CA certificate/key
/// from `slot`, returning the DER-encoded `CertificateList`.
pub fn generate_crl(
    yubikey: &mut YubiKey,
    slot: SlotId,
    ca_cert: &Certificate,
    revoked: &[RevokedEntry],
    next_update_days: u32,
    crl_number: Option<u64>,
) -> Result<Vec<u8>, AppError> {
    match detect_algorithm(ca_cert)? {
        CliAlgorithm::EccP256 => sign_crl_with::<p256::NistP256>(
            yubikey,
            slot,
            ca_cert,
            revoked,
            next_update_days,
            crl_number,
        ),
        CliAlgorithm::EccP384 => sign_crl_with::<p384::NistP384>(
            yubikey,
            slot,
            ca_cert,
            revoked,
            next_update_days,
            crl_number,
        ),
    }
}

fn sign_crl_with<KT: KeyType>(
    yubikey: &mut YubiKey,
    slot: SlotId,
    ca_cert: &Certificate,
    revoked: &[RevokedEntry],
    next_update_days: u32,
    crl_number: Option<u64>,
) -> Result<Vec<u8>, AppError> {
    use signature::Signer as _;

    let issuer_spki = ca_cert.subject_pki();
    let issuer = ca_cert.cert.tbs_certificate.subject.clone();
    let signer = Signer::<KT>::new(yubikey, slot, issuer_spki.clone())?;
    let signature_algorithm = signer.signature_algorithm_identifier()?;

    let this_update = Time::try_from(SystemTime::now())?;
    let next_update = checked_next_update(next_update_days)?;

    let revoked_certificates = if revoked.is_empty() {
        None
    } else {
        let mut entries = Vec::with_capacity(revoked.len());
        for entry in revoked {
            let crl_entry_extensions = match entry.reason {
                Some(reason) => Some(vec![reason.to_extension(&issuer, &[])?]),
                None => None,
            };
            entries.push(RevokedCert {
                serial_number: entry.serial.clone(),
                revocation_date: entry.revocation_date,
                crl_entry_extensions,
            });
        }
        Some(entries)
    };

    let mut crl_extensions =
        vec![AuthorityKeyIdentifier::try_from(issuer_spki)?.to_extension(&issuer, &[])?];
    if let Some(number) = crl_number {
        crl_extensions
            .push(CrlNumber(Uint::new(&number.to_be_bytes())?).to_extension(&issuer, &[])?);
    }

    let tbs_cert_list = TbsCertList {
        version: Version::V2,
        signature: signature_algorithm.clone(),
        issuer,
        this_update,
        next_update: Some(next_update),
        revoked_certificates,
        crl_extensions: Some(crl_extensions),
    };

    let tbs_der = tbs_cert_list.to_der()?;
    let signature_bytes: KT::Signature = signer.try_sign(&tbs_der)?;

    let certificate_list = CertificateList {
        tbs_cert_list,
        signature_algorithm,
        signature: signature_bytes.to_bitstring()?,
    };

    Ok(certificate_list.to_der()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_serial_only_line() {
        let entries = parse_revoked_line("1A2B3C").unwrap();
        assert_eq!(entries.serial.as_bytes(), [0x1a, 0x2b, 0x3c]);
        assert!(entries.reason.is_none());
    }

    #[test]
    fn parses_serial_with_colon_separators() {
        let entries = parse_revoked_line("1a:2b:3c").unwrap();
        assert_eq!(entries.serial.as_bytes(), [0x1a, 0x2b, 0x3c]);
    }

    #[test]
    fn parses_serial_with_hyphen_separators() {
        let entries = parse_revoked_line("1a-2b-3c").unwrap();
        assert_eq!(entries.serial.as_bytes(), [0x1a, 0x2b, 0x3c]);
    }

    #[test]
    fn parses_serial_date_and_reason() {
        let entry = parse_revoked_line("1A2B3C, 2026-01-15, key-compromise").unwrap();
        assert_eq!(entry.reason, Some(CrlReason::KeyCompromise));
        assert_eq!(entry.revocation_date.to_date_time().year(), 2026);
        assert_eq!(entry.revocation_date.to_date_time().month(), 1);
        assert_eq!(entry.revocation_date.to_date_time().day(), 15);
    }

    #[test]
    fn rejects_empty_serial() {
        assert!(parse_revoked_line("").is_err());
        assert!(parse_revoked_line(",2026-01-15").is_err());
    }

    #[test]
    fn rejects_invalid_serial_hex() {
        assert!(parse_revoked_line("not-hex-zzzz").is_err());
    }

    #[test]
    fn rejects_malformed_date() {
        assert!(parse_revoked_line("1A2B3C,2026/01/15").is_err());
    }

    #[test]
    fn rejects_unknown_reason() {
        assert!(parse_revoked_line("1A2B3C,2026-01-15,made-up-reason").is_err());
    }

    #[test]
    fn checked_next_update_rejects_overflow_instead_of_panicking() {
        assert!(checked_next_update(u32::MAX).is_err());
    }

    #[test]
    fn checked_next_update_rejects_a_date_x509_cannot_encode() {
        // About the year 10200: inside SystemTime's range on every platform, past the year 9999
        // that X.509's GeneralizedTime ends at.
        assert!(checked_next_update(3_000_000).is_err());
    }

    #[test]
    fn checked_next_update_accepts_an_ordinary_interval() {
        assert!(checked_next_update(30).is_ok());
    }

    #[test]
    fn ignores_blank_and_comment_lines() {
        let entries =
            parse_revoked_file_from_str("# comment\n\n1A2B3C\n  \n2A2B2C,2026-02-01\n").unwrap();
        assert_eq!(entries.len(), 2);
    }

    fn parse_revoked_file_from_str(content: &str) -> Result<Vec<RevokedEntry>, AppError> {
        let mut entries = Vec::new();
        for (line_number, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let entry = parse_revoked_line(line).map_err(|err| {
                AppError::InvalidCrlInput(format!("line {}: {err}", line_number + 1))
            })?;
            entries.push(entry);
        }
        Ok(entries)
    }
}
