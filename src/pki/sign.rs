use tracing::warn;
use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    der::referenced::OwnedToRef,
    ext::Extension,
    request::CertReq,
    time::Validity,
};
use yubikey::{
    YubiKey,
    certificate::{Certificate, yubikey_signer::Signer},
    piv::SlotId,
};

use crate::{
    cli::CliAlgorithm,
    error::AppError,
    hardware::device::{export_certificate_pem, print_certificate_details},
    io::OutputPlan,
    pki::{
        algorithm::detect_algorithm, csr::add_supported_csr_extensions,
        serial::generate_serial_number,
    },
};

/// Signs `csr` against `ca_cert` and exports the resulting certificate to
/// `output`, printing its details. Shared by `sign-csr` and `issue-host`,
/// which differ only in the log line they emit once this returns and in
/// `force_ca` (always `false` for `issue-host`, which never issues a CA).
///
/// `csr_extensions` is the CSR's already-decoded requested-extensions list
/// (see `pki::csr::csr_requested_extensions`); it's taken as a parameter
/// rather than decoded here because `sign-csr` also needs it to print the
/// CSR's details before signing, and decoding it twice would be wasted work.
#[allow(clippy::too_many_arguments)]
pub fn sign_and_export(
    yubikey: &mut YubiKey,
    slot: SlotId,
    ca_cert: &Certificate,
    csr: &CertReq,
    csr_extensions: &[Extension],
    validity: Validity,
    force_ca: bool,
    output: &OutputPlan,
) -> Result<Certificate, AppError> {
    let cert = sign_loaded_csr(
        yubikey,
        slot,
        ca_cert,
        csr,
        csr_extensions,
        validity,
        force_ca,
    )?;
    export_certificate_pem(&cert, &output.crt_path())?;
    print_certificate_details(slot, &cert);
    Ok(cert)
}

pub fn sign_loaded_csr(
    yubikey: &mut YubiKey,
    slot: SlotId,
    ca_cert: &Certificate,
    csr: &CertReq,
    csr_extensions: &[Extension],
    validity: Validity,
    force_ca: bool,
) -> Result<Certificate, AppError> {
    let validity = clamp_to_issuer(validity, ca_cert, slot);
    match detect_algorithm(ca_cert)? {
        CliAlgorithm::EccP256 => sign_with::<p256::NistP256>(
            yubikey,
            slot,
            ca_cert,
            csr,
            csr_extensions,
            validity,
            force_ca,
        ),
        CliAlgorithm::EccP384 => sign_with::<p384::NistP384>(
            yubikey,
            slot,
            ca_cert,
            csr,
            csr_extensions,
            validity,
            force_ca,
        ),
    }
}

/// A CA must never issue a certificate that outlives its own certificate:
/// clamp `not_after` down to the issuer's own expiry if the caller asked for more.
fn clamp_to_issuer(validity: Validity, ca_cert: &Certificate, slot: SlotId) -> Validity {
    let issuer_not_after = ca_cert.cert.tbs_certificate.validity.not_after;

    if validity.not_after.to_date_time() <= issuer_not_after.to_date_time() {
        return validity;
    }

    warn!(
        slot = %slot,
        "requested validity exceeds issuer certificate expiry; clamping not_after to issuer expiry"
    );
    Validity {
        not_before: validity.not_before,
        not_after: issuer_not_after,
    }
}

fn sign_with<KT: yubikey::certificate::yubikey_signer::KeyType>(
    yubikey: &mut YubiKey,
    slot: SlotId,
    ca_cert: &Certificate,
    csr: &CertReq,
    csr_extensions: &[Extension],
    validity: Validity,
    force_ca: bool,
) -> Result<Certificate, AppError> {
    let issuer_spki = ca_cert.subject_pki();
    let signer = Signer::<KT>::new(yubikey, slot, issuer_spki.clone())?;
    let serial = generate_serial_number()?;

    let mut builder = CertificateBuilder::new(
        Profile::Manual {
            issuer: Some(ca_cert.cert.tbs_certificate.subject.clone()),
        },
        serial,
        validity,
        csr.info.subject.clone(),
        csr.info.public_key.clone(),
        &signer,
    )?;

    add_supported_csr_extensions(
        &mut builder,
        csr_extensions,
        csr.info.public_key.owned_to_ref(),
        issuer_spki,
        force_ca,
    )?;

    let cert = builder.build()?;
    Ok(Certificate { cert })
}
