use std::str::FromStr;

use tracing::info;

use crate::{
    cli::InitCaArgs,
    error::AppError,
    hardware::device::{
        ensure_slot_can_be_initialized, open_yubikey, print_certificate_details, print_device_info,
    },
    hardware::management::{
        ensure_non_default_management_key, ensure_non_default_pin, parse_management_key,
    },
    pki::ca_cert::{CaProfile, generate_root_ca},
    pki::validity::build_validity,
};

pub fn run(args: &InitCaArgs) -> Result<(), AppError> {
    let mut yubikey = open_yubikey(args.serial)?;
    let (profile, mgm_key, uses_default_mgm_key) = build_ca_profile(args)?;

    print_device_info(&mut yubikey);
    ensure_non_default_management_key(uses_default_mgm_key)?;
    ensure_slot_can_be_initialized(&mut yubikey, profile.slot, args.force)?;
    yubikey.authenticate(mgm_key)?;

    let cert = generate_root_ca(&mut yubikey, &profile)?;

    info!(slot = %profile.slot, "initialized root ca");
    print_certificate_details(profile.slot, &cert);

    Ok(())
}

fn build_ca_profile(args: &InitCaArgs) -> Result<(CaProfile, yubikey::MgmKey, bool), AppError> {
    let subject = x509_cert::name::Name::from_str(&args.subject)
        .map_err(|err| AppError::InvalidSubject(err.to_string()))?;
    let validity = build_validity(
        args.validity.valid_years,
        args.validity.valid_months,
        args.validity.valid_days,
        crate::defaults::CaDefaults::VALID_YEARS,
    )?;

    let pin = args
        .pin
        .pin
        .as_deref()
        .ok_or(AppError::PinRequiredForCaInitialization)?;
    ensure_non_default_pin(pin)?;

    let (mgm_key, uses_default_mgm_key) = parse_management_key(args.mgm_key_hex.as_deref())?;

    Ok((
        CaProfile {
            subject,
            validity,
            algorithm: args.algorithm,
            pin_policy: args.pin_policy.into(),
            touch_policy: args.touch_policy.into(),
            slot: args.slot,
            pin: Some(pin.to_owned()),
        },
        mgm_key,
        uses_default_mgm_key,
    ))
}
