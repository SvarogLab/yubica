use std::{fs, path::Path};

use pem_rfc7468::LineEnding;
use tracing::{debug, info, warn};
use x509_cert::der::Encode;
use yubikey::{
    YubiKey,
    certificate::Certificate,
    piv::{self, SlotId},
};

use crate::error::AppError;

/// Opens the YubiKey with the given serial number. `serial` is a mandatory
/// CLI/env argument precisely so an operator never operates on whichever
/// device happens to be plugged in when more than one is connected.
pub fn open_yubikey(serial: u32) -> Result<YubiKey, AppError> {
    Ok(YubiKey::open_by_serial(serial.into())?)
}

pub fn print_device_info(yubikey: &mut YubiKey) {
    info!(reader = %yubikey.name(), "connected reader");
    info!(serial = %yubikey.serial(), version = ?yubikey.version(), "device information");

    match yubikey.get_pin_retries() {
        Ok(retries) => info!(pin_retries_left = retries, "pin retries"),
        Err(err) => warn!(error = ?err, "failed to read pin retries"),
    }

    match yubikey.chuid() {
        Ok(chuid) => debug!(chuid = ?chuid, "read chuid"),
        Err(err) => warn!(error = ?err, "failed to read chuid"),
    }

    match yubikey.cccid() {
        Ok(cccid) => debug!(cccid = ?cccid, "read cccid"),
        Err(err) => warn!(error = ?err, "failed to read cccid"),
    }
}

pub fn read_slot_certificate(yubikey: &mut YubiKey, slot: SlotId) -> Option<Certificate> {
    info!(slot = %slot, "probing slot");

    match Certificate::read(yubikey, slot) {
        Ok(cert) => {
            info!(slot = %slot, subject = %cert.subject(), issuer = %cert.issuer(), "certificate present");
            Some(cert)
        }
        Err(err) => {
            debug!(slot = %slot, error = ?err, "certificate missing or unreadable");
            None
        }
    }
}

pub fn print_certificate_details(slot: SlotId, cert: &Certificate) {
    let tbs = &cert.cert.tbs_certificate;

    info!(
        slot = %slot,
        version = ?tbs.version,
        serial = ?tbs.serial_number,
        subject = %cert.subject(),
        issuer = %cert.issuer(),
        validity = ?tbs.validity,
        signature_algorithm = ?cert.cert.signature_algorithm,
        "certificate details"
    );
}

pub fn export_certificate_pem(cert: &Certificate, path: &Path) -> Result<(), AppError> {
    let der = cert.cert.to_der()?;
    let pem = pem_rfc7468::encode_string("CERTIFICATE", LineEnding::LF, &der)
        .map_err(|err| std::io::Error::other(format!("PEM encoding failed: {err:?}")))?;
    fs::write(path, pem)?;
    Ok(())
}

pub fn ensure_slot_can_be_initialized(
    yubikey: &mut YubiKey,
    slot: SlotId,
    force: bool,
) -> Result<(), AppError> {
    if force {
        return Ok(());
    }

    if Certificate::read(yubikey, slot).is_ok() || piv::metadata(yubikey, slot).is_ok() {
        return Err(AppError::SlotOccupied { slot });
    }

    Ok(())
}
