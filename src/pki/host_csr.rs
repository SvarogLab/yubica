use std::net::IpAddr;
use std::str::FromStr;

use pkcs8::{EncodePrivateKey, LineEnding};
use rand::rngs::OsRng;
use x509_cert::{
    builder::{Builder, RequestBuilder},
    der::{EncodePem, asn1::Ia5String},
    ext::pkix::{ExtendedKeyUsage, SubjectAltName, name::GeneralName},
    name::Name,
    request::CertReq,
};

use crate::{cli::CliAlgorithm, defaults::HostDefaults, error::AppError};

pub enum HostArtifacts {
    EccP256 { key: p256::SecretKey, csr: CertReq },
    EccP384 { key: p384::SecretKey, csr: CertReq },
}

pub fn host_subject(subject: Option<&str>, hosts: &[String]) -> Result<Name, AppError> {
    if let Some(subject) = subject {
        return Name::from_str(subject).map_err(|err| AppError::InvalidSubject(err.to_string()));
    }

    let cn = hosts
        .first()
        .ok_or_else(|| AppError::InvalidSubject("at least one host is required".into()))?;
    Name::from_str(&format!("CN={cn}")).map_err(|err| AppError::InvalidSubject(err.to_string()))
}

pub fn generate_host_artifacts(
    algorithm: CliAlgorithm,
    subject: Name,
    hosts: &[String],
) -> Result<HostArtifacts, AppError> {
    match algorithm {
        CliAlgorithm::EccP256 => {
            let key = p256::SecretKey::random(&mut OsRng);
            let signer = p256::ecdsa::SigningKey::from(key.clone());
            Ok(HostArtifacts::EccP256 {
                key,
                csr: build_p256_host_csr(&subject, hosts, &signer)?,
            })
        }
        CliAlgorithm::EccP384 => {
            let key = p384::SecretKey::random(&mut OsRng);
            let signer = p384::ecdsa::SigningKey::from(key.clone());
            Ok(HostArtifacts::EccP384 {
                key,
                csr: build_p384_host_csr(&subject, hosts, &signer)?,
            })
        }
    }
}

fn build_p256_host_csr(
    subject: &Name,
    hosts: &[String],
    signer: &p256::ecdsa::SigningKey,
) -> Result<CertReq, AppError> {
    let mut builder = RequestBuilder::new(subject.clone(), signer)?;
    builder.add_extension(&subject_alt_name(hosts)?)?;
    builder.add_extension(&server_auth_eku())?;
    builder.add_extension(&HostDefaults::basic_constraints())?;
    builder.add_extension(&HostDefaults::key_usage())?;
    Ok(builder.build::<p256::ecdsa::DerSignature>()?)
}

fn build_p384_host_csr(
    subject: &Name,
    hosts: &[String],
    signer: &p384::ecdsa::SigningKey,
) -> Result<CertReq, AppError> {
    let mut builder = RequestBuilder::new(subject.clone(), signer)?;
    builder.add_extension(&subject_alt_name(hosts)?)?;
    builder.add_extension(&server_auth_eku())?;
    builder.add_extension(&HostDefaults::basic_constraints())?;
    builder.add_extension(&HostDefaults::key_usage())?;
    Ok(builder.build::<p384::ecdsa::DerSignature>()?)
}

fn subject_alt_name(hosts: &[String]) -> Result<SubjectAltName, AppError> {
    let mut names = Vec::with_capacity(hosts.len());
    for host in hosts {
        if let Ok(ip) = IpAddr::from_str(host) {
            names.push(GeneralName::from(ip));
        } else {
            let dns = Ia5String::new(host.as_str())
                .map_err(|err| AppError::InvalidCsr(err.to_string()))?;
            names.push(GeneralName::DnsName(dns));
        }
    }
    Ok(SubjectAltName(names))
}

fn server_auth_eku() -> ExtendedKeyUsage {
    ExtendedKeyUsage(vec![const_oid::ObjectIdentifier::new_unwrap(
        "1.3.6.1.5.5.7.3.1",
    )])
}

pub fn private_key_pem(
    artifacts: &HostArtifacts,
    password: Option<&str>,
) -> Result<String, AppError> {
    match artifacts {
        HostArtifacts::EccP256 { key, .. } => encode_private_key(key, password),
        HostArtifacts::EccP384 { key, .. } => encode_private_key(key, password),
    }
}

fn encode_private_key<K>(key: &K, password: Option<&str>) -> Result<String, AppError>
where
    K: EncodePrivateKey,
{
    match password {
        Some(password) => key
            .to_pkcs8_encrypted_pem(&mut OsRng, password, LineEnding::LF)
            .map(|pem| pem.to_string())
            .map_err(|_| AppError::UnsupportedPasswordEncryption("private key")),
        None => Ok(key.to_pkcs8_pem(LineEnding::LF)?.to_string()),
    }
}

pub fn csr_ref(artifacts: &HostArtifacts) -> &CertReq {
    match artifacts {
        HostArtifacts::EccP256 { csr, .. } | HostArtifacts::EccP384 { csr, .. } => csr,
    }
}

pub fn csr_pem(csr: &CertReq) -> Result<String, AppError> {
    Ok(csr.to_pem(LineEnding::LF)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_subject_uses_explicit_subject_when_given() {
        let subject = host_subject(Some("CN=example.internal"), &[]).unwrap();
        assert_eq!(subject.to_string(), "CN=example.internal");
    }

    #[test]
    fn host_subject_defaults_to_cn_of_first_host() {
        let hosts = vec!["api.example.internal".to_string(), "10.0.0.1".to_string()];
        let subject = host_subject(None, &hosts).unwrap();
        assert_eq!(subject.to_string(), "CN=api.example.internal");
    }

    #[test]
    fn host_subject_requires_at_least_one_host_without_explicit_subject() {
        assert!(host_subject(None, &[]).is_err());
    }

    #[test]
    fn subject_alt_name_classifies_ips_and_dns_names() {
        let hosts = vec![
            "api.example.internal".to_string(),
            "10.0.0.20".to_string(),
            "::1".to_string(),
        ];
        let san = subject_alt_name(&hosts).unwrap();
        assert_eq!(san.0.len(), 3);
        assert!(matches!(san.0[0], GeneralName::DnsName(_)));
        assert!(matches!(san.0[1], GeneralName::IpAddress(_)));
        assert!(matches!(san.0[2], GeneralName::IpAddress(_)));
    }
}
