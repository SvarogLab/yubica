use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    der::referenced::OwnedToRef,
    ext::pkix::SubjectKeyIdentifier,
    name::Name,
    time::Validity,
};
use yubikey::{
    PinPolicy, TouchPolicy, YubiKey,
    certificate::{
        CertInfo, Certificate,
        yubikey_signer::{KeyType, Signer},
    },
    piv,
};

use crate::{
    cli::CliAlgorithm, defaults::CaDefaults, error::AppError, pki::serial::generate_serial_number,
};

#[derive(Clone)]
pub struct CaProfile {
    pub subject: Name,
    pub validity: Validity,
    pub algorithm: CliAlgorithm,
    pub pin_policy: PinPolicy,
    pub touch_policy: TouchPolicy,
    pub slot: piv::SlotId,
    pub pin: Option<String>,
}

pub fn generate_root_ca(
    yubikey: &mut YubiKey,
    profile: &CaProfile,
) -> Result<Certificate, AppError> {
    match profile.algorithm {
        CliAlgorithm::EccP256 => generate_with::<p256::NistP256>(yubikey, profile),
        CliAlgorithm::EccP384 => generate_with::<p384::NistP384>(yubikey, profile),
    }
}

fn generate_with<KT: KeyType>(
    yubikey: &mut YubiKey,
    profile: &CaProfile,
) -> Result<Certificate, AppError> {
    let subject_pki = piv::generate(
        yubikey,
        profile.slot,
        profile.algorithm.into(),
        profile.pin_policy,
        profile.touch_policy,
    )?;

    if let Some(pin) = profile.pin.as_deref() {
        yubikey.verify_pin(pin.as_bytes())?;
    }

    let extension_subject_pki = subject_pki.clone();
    let subject_pki_ref = extension_subject_pki.owned_to_ref();
    let signer = Signer::<KT>::new(yubikey, profile.slot, subject_pki_ref.clone())?;
    let serial = generate_serial_number()?;

    let mut builder = CertificateBuilder::new(
        Profile::Manual { issuer: None },
        serial,
        profile.validity,
        profile.subject.clone(),
        subject_pki,
        &signer,
    )?;

    add_ca_extensions(&mut builder, subject_pki_ref)?;

    let cert = builder.build()?;
    let cert = Certificate { cert };
    cert.write(yubikey, profile.slot, CertInfo::Uncompressed)?;
    Ok(cert)
}

fn add_ca_extensions<KT: KeyType>(
    builder: &mut CertificateBuilder<'_, Signer<'_, KT>>,
    subject_pki: x509_cert::spki::SubjectPublicKeyInfoRef<'_>,
) -> Result<(), AppError> {
    let key_usage = CaDefaults::key_usage();
    let basic_constraints = CaDefaults::basic_constraints();
    let subject_key_identifier = SubjectKeyIdentifier::try_from(subject_pki)?;

    builder.add_extension(&key_usage)?;
    builder.add_extension(&basic_constraints)?;
    builder.add_extension(&subject_key_identifier)?;
    Ok(())
}
