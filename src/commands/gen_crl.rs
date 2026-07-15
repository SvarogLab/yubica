use std::fs;

use pem_rfc7468::LineEnding;
use tracing::info;
use yubikey::certificate::Certificate;

use crate::{
    cli::GenCrlArgs,
    error::AppError,
    hardware::device::{open_yubikey, print_device_info},
    io::OutputPlan,
    pki::crl::{generate_crl, parse_revoked_file},
};

pub fn run(args: &GenCrlArgs) -> Result<(), AppError> {
    let mut yubikey = open_yubikey(args.serial)?;
    let output = OutputPlan::new(&args.iopath, &args.filename)?;
    print_device_info(&mut yubikey);

    let ca_cert = Certificate::read(&mut yubikey, args.slot)?;
    if let Some(pin) = args.pin.pin.as_deref() {
        yubikey.verify_pin(pin.as_bytes())?;
    }

    let revoked = parse_revoked_file(&args.revoked)?;
    info!(count = revoked.len(), "loaded revoked certificate entries");

    let der = generate_crl(
        &mut yubikey,
        args.slot,
        &ca_cert,
        &revoked,
        args.next_update_days,
        args.crl_number,
    )?;
    let pem = pem_rfc7468::encode_string("X509 CRL", LineEnding::LF, &der)
        .map_err(|err| std::io::Error::other(format!("PEM encoding failed: {err:?}")))?;
    fs::write(output.crl_path(), pem)?;

    info!(path = %output.crl_path().display(), "exported crl");
    Ok(())
}
