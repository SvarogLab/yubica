use const_oid::ObjectIdentifier;
use x509_cert::der::{Decode, Encode};
use yubikey::certificate::Certificate;

use crate::{cli::CliAlgorithm, error::AppError};

const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

/// Identifies the curve of a CA's subject public key by decoding the SPKI
/// algorithm parameters as a typed OID, rather than comparing raw DER bytes.
pub fn detect_algorithm(ca_cert: &Certificate) -> Result<CliAlgorithm, AppError> {
    let spki = ca_cert.subject_pki();
    // `AnyRef::value()` strips the parameter's own tag+length (it only returns
    // the inner content octets); re-encoding via `to_der()` restores the full
    // tag+length+content TLV that `algorithm_from_oid` expects to decode.
    let ec_params = spki
        .algorithm
        .parameters
        .map(|params| params.to_der())
        .transpose()?;
    algorithm_from_oid(spki.algorithm.oid, ec_params.as_deref())
}

fn algorithm_from_oid(
    oid: ObjectIdentifier,
    ec_params: Option<&[u8]>,
) -> Result<CliAlgorithm, AppError> {
    if oid != OID_EC_PUBLIC_KEY {
        return Err(AppError::InvalidCsr(format!(
            "unsupported CA SPKI algorithm oid: {oid}"
        )));
    }

    let params = ec_params.ok_or_else(|| AppError::InvalidCsr("missing EC parameters".into()))?;
    let curve_oid = ObjectIdentifier::from_der(params)
        .map_err(|err| AppError::InvalidCsr(format!("invalid EC curve parameters: {err}")))?;

    if curve_oid == OID_SECP256R1 {
        Ok(CliAlgorithm::EccP256)
    } else if curve_oid == OID_SECP384R1 {
        Ok(CliAlgorithm::EccP384)
    } else {
        Err(AppError::InvalidCsr(format!(
            "unsupported EC curve oid: {curve_oid}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use x509_cert::der::Encode;

    use super::*;

    fn der(oid: &ObjectIdentifier) -> Vec<u8> {
        oid.to_der().unwrap()
    }

    #[test]
    fn accepts_secp256r1() {
        let result = algorithm_from_oid(OID_EC_PUBLIC_KEY, Some(&der(&OID_SECP256R1)));
        assert_eq!(result.unwrap(), CliAlgorithm::EccP256);
    }

    #[test]
    fn accepts_secp384r1() {
        let result = algorithm_from_oid(OID_EC_PUBLIC_KEY, Some(&der(&OID_SECP384R1)));
        assert_eq!(result.unwrap(), CliAlgorithm::EccP384);
    }

    #[test]
    fn rejects_non_ec_algorithm() {
        let rsa_oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
        let result = algorithm_from_oid(rsa_oid, Some(&der(&OID_SECP256R1)));
        assert!(result.is_err());
    }

    #[test]
    fn rejects_unsupported_curve() {
        let secp256k1 = ObjectIdentifier::new_unwrap("1.3.132.0.10");
        let result = algorithm_from_oid(OID_EC_PUBLIC_KEY, Some(&der(&secp256k1)));
        assert!(result.is_err());
    }

    #[test]
    fn rejects_missing_parameters() {
        let result = algorithm_from_oid(OID_EC_PUBLIC_KEY, None);
        assert!(result.is_err());
    }
}
