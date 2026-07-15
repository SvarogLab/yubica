use tracing::info;
use yubikey::certificate::Certificate;

use crate::{
    cli::SignCsrArgs,
    defaults::CsrDefaults,
    error::AppError,
    hardware::device::{open_yubikey, print_device_info},
    io::OutputPlan,
    pki::csr::{csr_requested_extensions, load_csr, print_csr_details},
    pki::sign::sign_and_export,
    pki::validity::build_validity,
};

pub fn run(args: &SignCsrArgs) -> Result<(), AppError> {
    let mut yubikey = open_yubikey(args.serial)?;
    let output = OutputPlan::new(&args.iopath, &args.filename)?;
    print_device_info(&mut yubikey);

    let csr = load_csr(&output.csr_path())?;
    let csr_extensions = csr_requested_extensions(&csr)?;
    print_csr_details(&csr, &csr_extensions);
    let ca_cert = Certificate::read(&mut yubikey, args.slot)?;

    if let Some(pin) = args.pin.pin.as_deref() {
        yubikey.verify_pin(pin.as_bytes())?;
    }

    let validity = build_validity(
        args.validity.valid_years,
        args.validity.valid_months,
        args.validity.valid_days,
        CsrDefaults::VALID_YEARS,
    )?;
    sign_and_export(
        &mut yubikey,
        args.slot,
        &ca_cert,
        &csr,
        &csr_extensions,
        validity,
        args.ca,
        &output,
    )?;

    info!(path = %output.crt_path().display(), "exported signed certificate");
    Ok(())
}
