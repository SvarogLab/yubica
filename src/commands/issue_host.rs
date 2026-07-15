use std::fs;

use tracing::info;

use crate::{
    cli::IssueHostArgs,
    defaults::HostDefaults,
    error::AppError,
    hardware::device::{open_yubikey, print_device_info},
    io::OutputPlan,
    pki::csr::csr_requested_extensions,
    pki::host_csr::{csr_pem, csr_ref, generate_host_artifacts, host_subject, private_key_pem},
    pki::sign::sign_and_export,
    pki::validity::build_validity,
};

pub fn run(args: &IssueHostArgs) -> Result<(), AppError> {
    let mut yubikey = open_yubikey(args.serial)?;
    print_device_info(&mut yubikey);

    let output = OutputPlan::new(&args.iopath, &args.filename)?;
    let subject = host_subject(args.subject.as_deref(), &args.host)?;
    let artifacts = generate_host_artifacts(args.algorithm, subject, &args.host)?;

    fs::write(
        output.key_path(),
        private_key_pem(&artifacts, args.passwd.as_deref())?,
    )?;
    fs::write(output.csr_path(), csr_pem(csr_ref(&artifacts))?)?;

    let ca_cert = yubikey::certificate::Certificate::read(&mut yubikey, args.slot)?;
    if let Some(pin) = args.pin.pin.as_deref() {
        yubikey.verify_pin(pin.as_bytes())?;
    }

    let validity = build_validity(
        args.validity.valid_years,
        args.validity.valid_months,
        args.validity.valid_days,
        HostDefaults::VALID_YEARS,
    )?;
    let csr_extensions = csr_requested_extensions(csr_ref(&artifacts))?;
    sign_and_export(
        &mut yubikey,
        args.slot,
        &ca_cert,
        csr_ref(&artifacts),
        &csr_extensions,
        validity,
        false,
        &output,
    )?;

    info!(path = %output.key_path().display(), "exported host private key");
    info!(path = %output.csr_path().display(), "exported host csr");
    info!(path = %output.crt_path().display(), "exported host certificate");
    Ok(())
}
