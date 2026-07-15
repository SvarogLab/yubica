use std::{fs, path::Path};

use const_oid::AssociatedOid;
use const_oid::db::rfc5912::ID_EXTENSION_REQ;
use tracing::{info, warn};
use x509_cert::{
    der::Decode,
    ext::{
        Extension,
        pkix::{
            AuthorityKeyIdentifier, ExtendedKeyUsage, KeyUsage, SubjectAltName,
            SubjectKeyIdentifier, constraints::BasicConstraints, name::GeneralName,
        },
    },
    request::{CertReq, ExtensionReq},
};

use crate::{defaults::CaDefaults, error::AppError};

pub fn load_csr(path: &Path) -> Result<CertReq, AppError> {
    let input = fs::read(path)?;
    let der = if input.starts_with(b"-----BEGIN") {
        let (label, der) =
            pem_rfc7468::decode_vec(&input).map_err(|err| AppError::InvalidCsr(err.to_string()))?;
        if label != "CERTIFICATE REQUEST" && label != "NEW CERTIFICATE REQUEST" {
            return Err(AppError::InvalidCsr(format!(
                "unexpected PEM label: {label}"
            )));
        }
        der
    } else {
        input
    };

    CertReq::from_der(&der).map_err(|err| AppError::InvalidCsr(err.to_string()))
}

/// Prints the CSR's subject and requested extensions so an operator can
/// review what's about to be signed before the YubiKey prompts for a touch.
/// Takes the already-decoded `extensions` (see [`csr_requested_extensions`])
/// rather than decoding them again, since the caller needs that same list to
/// actually sign the CSR.
pub fn print_csr_details(csr: &CertReq, extensions: &[Extension]) {
    let mut requested_extensions = Vec::with_capacity(extensions.len());
    let mut subject_alt_names = Vec::new();

    for extension in extensions {
        if extension.extn_id == BasicConstraints::OID {
            requested_extensions.push("BasicConstraints".to_string());
        } else if extension.extn_id == KeyUsage::OID {
            requested_extensions.push("KeyUsage".to_string());
        } else if extension.extn_id == ExtendedKeyUsage::OID {
            requested_extensions.push("ExtendedKeyUsage".to_string());
        } else if extension.extn_id == SubjectAltName::OID {
            requested_extensions.push("SubjectAltName".to_string());
            match SubjectAltName::from_der(extension.extn_value.as_bytes()) {
                Ok(san) => subject_alt_names.extend(san.0.iter().map(describe_general_name)),
                Err(err) => warn!(
                    oid = %extension.extn_id,
                    error = ?err,
                    "failed to decode requested SubjectAltName"
                ),
            }
        } else {
            requested_extensions.push(format!("unsupported({})", extension.extn_id));
        }
    }

    info!(
        subject = %csr.info.subject,
        requested_extensions = ?requested_extensions,
        subject_alt_names = ?subject_alt_names,
        "csr details"
    );
}

fn describe_general_name(name: &GeneralName) -> String {
    match name {
        GeneralName::DnsName(dns) => dns.as_str().to_string(),
        GeneralName::IpAddress(ip) => match *ip.as_bytes() {
            [a, b, c, d] => std::net::Ipv4Addr::new(a, b, c, d).to_string(),
            [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p] => {
                std::net::Ipv6Addr::from([a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p])
                    .to_string()
            }
            _ => format!("{ip:?}"),
        },
        other => format!("{other:?}"),
    }
}

pub fn csr_requested_extensions(csr: &CertReq) -> Result<Vec<Extension>, AppError> {
    for attr in csr.info.attributes.iter() {
        if attr.oid == ID_EXTENSION_REQ
            && let Some(value) = attr.values.get(0)
        {
            let extension_req = value
                .decode_as::<ExtensionReq>()
                .map_err(|err| AppError::InvalidCsr(err.to_string()))?;
            return Ok(extension_req.0);
        }
    }

    Ok(Vec::new())
}

/// Rejects a CSR-requested `BasicConstraints` that asks for `CA:TRUE`: without
/// `--ca`, the signer must never honor a CSR's own claim to be a CA (that
/// claim is only ever advisory), so this either passes the extension through
/// unchanged (`CA:FALSE`) or refuses to sign at all.
fn ensure_leaf_basic_constraints(extension_value: &[u8]) -> Result<BasicConstraints, AppError> {
    let basic_constraints = BasicConstraints::from_der(extension_value)?;
    if basic_constraints.ca {
        return Err(AppError::CsrRequestsCaWithoutCaFlag);
    }
    Ok(basic_constraints)
}

/// Same reasoning as [`ensure_leaf_basic_constraints`], for the `KeyUsage`
/// bits (`keyCertSign`/`cRLSign`) that actually grant CA signing capability.
fn ensure_leaf_key_usage(extension_value: &[u8]) -> Result<KeyUsage, AppError> {
    let key_usage = KeyUsage::from_der(extension_value)?;
    if key_usage.key_cert_sign() || key_usage.crl_sign() {
        return Err(AppError::CsrRequestsCaWithoutCaFlag);
    }
    Ok(key_usage)
}

/// `force_ca` asserts CA:TRUE/keyCertSign+cRLSign on the issued certificate
/// regardless of what the CSR itself requested for those two extensions:
/// whether a certificate is a CA is the signer's decision, not the
/// requester's, so a CSR's own `BasicConstraints`/`KeyUsage` are only ever
/// advisory and must not be trusted for that decision. Without `--ca`, a CSR
/// that requests CA capabilities is refused rather than silently honored or
/// silently downgraded.
pub fn add_supported_csr_extensions<KT: yubikey::certificate::yubikey_signer::KeyType>(
    builder: &mut x509_cert::builder::CertificateBuilder<
        '_,
        yubikey::certificate::yubikey_signer::Signer<'_, KT>,
    >,
    csr_extensions: &[Extension],
    csr_spki: x509_cert::spki::SubjectPublicKeyInfoRef<'_>,
    issuer_spki: x509_cert::spki::SubjectPublicKeyInfoRef<'_>,
    force_ca: bool,
) -> Result<(), AppError> {
    if force_ca {
        builder.add_extension(&CaDefaults::basic_constraints())?;
        builder.add_extension(&CaDefaults::key_usage())?;
    }

    for extension in csr_extensions {
        if extension.extn_id == BasicConstraints::OID {
            if force_ca {
                warn!("ignoring csr-requested BasicConstraints; --ca forces CA:TRUE");
                continue;
            }
            builder.add_extension(&ensure_leaf_basic_constraints(
                extension.extn_value.as_bytes(),
            )?)?;
        } else if extension.extn_id == KeyUsage::OID {
            if force_ca {
                warn!("ignoring csr-requested KeyUsage; --ca forces keyCertSign/cRLSign");
                continue;
            }
            builder.add_extension(&ensure_leaf_key_usage(extension.extn_value.as_bytes())?)?;
        } else if extension.extn_id == SubjectAltName::OID {
            builder.add_extension(&SubjectAltName::from_der(extension.extn_value.as_bytes())?)?;
        } else if extension.extn_id == ExtendedKeyUsage::OID {
            builder.add_extension(&ExtendedKeyUsage::from_der(
                extension.extn_value.as_bytes(),
            )?)?;
        } else {
            warn!(oid = %extension.extn_id, "ignoring unsupported csr extension request");
        }
    }

    builder.add_extension(&SubjectKeyIdentifier::try_from(csr_spki)?)?;
    builder.add_extension(&AuthorityKeyIdentifier::try_from(issuer_spki)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use x509_cert::der::Encode;
    use x509_cert::ext::pkix::KeyUsages;

    use super::*;

    #[test]
    fn rejects_ca_true_basic_constraints() {
        let der = BasicConstraints {
            ca: true,
            path_len_constraint: None,
        }
        .to_der()
        .unwrap();
        assert!(ensure_leaf_basic_constraints(&der).is_err());
    }

    #[test]
    fn accepts_ca_false_basic_constraints() {
        let der = BasicConstraints {
            ca: false,
            path_len_constraint: None,
        }
        .to_der()
        .unwrap();
        assert!(ensure_leaf_basic_constraints(&der).is_ok());
    }

    #[test]
    fn rejects_key_cert_sign() {
        let der = KeyUsage(KeyUsages::KeyCertSign.into()).to_der().unwrap();
        assert!(ensure_leaf_key_usage(&der).is_err());
    }

    #[test]
    fn rejects_crl_sign() {
        let der = KeyUsage(KeyUsages::CRLSign.into()).to_der().unwrap();
        assert!(ensure_leaf_key_usage(&der).is_err());
    }

    #[test]
    fn accepts_non_ca_key_usage() {
        let der = KeyUsage(KeyUsages::DigitalSignature.into())
            .to_der()
            .unwrap();
        assert!(ensure_leaf_key_usage(&der).is_ok());
    }
}
