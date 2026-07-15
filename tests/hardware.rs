//! Integration tests that talk to a real, connected YubiKey.
//!
//! These never run by default: they require `--features hardware-tests` at
//! compile time. There's no separate runtime "are you sure" flag on top of
//! that — the required environment variables (`YUBICA_TEST_SERIAL` and, for
//! the destructive test, `YUBICA_TEST_PIN`/`YUBICA_TEST_MGM_KEY_HEX`) already
//! are the opt-in: every command requires an explicit `--serial`, so these
//! tests only ever address the device pinned by `YUBICA_TEST_SERIAL`, never
//! "whichever YubiKey happens to be plugged in". See README.md for the full
//! list of required environment variables.
#![cfg(feature = "hardware-tests")]

use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};

use x509_cert::der::Decode;
use yubica::cli::{
    CliAlgorithm, CliPinPolicy, CliTouchPolicy, GenCrlArgs, GetCaArgs, InitCaArgs, IssueHostArgs,
    PinArg, SignCsrArgs, ValidityArgs,
};
use yubica::commands::{gen_crl, get_ca, init_ca, issue_host, sign_csr};
use yubikey::piv::SlotId;

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "yubica-hardware-test-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("set {name} to run hardware integration tests"))
}

fn test_serial() -> u32 {
    required_env("YUBICA_TEST_SERIAL")
        .parse()
        .expect("YUBICA_TEST_SERIAL must be numeric")
}

fn test_slot() -> SlotId {
    std::env::var("YUBICA_TEST_SLOT")
        .ok()
        .map(|value| SlotId::from_str(&value).expect("invalid YUBICA_TEST_SLOT"))
        .unwrap_or(SlotId::Signature)
}

/// Writes a minimal self-signed CSR requesting `BasicConstraints{ca}` to
/// `path`, so tests can exercise `sign-csr`'s CA-request handling without
/// depending on any external CSR generator.
fn write_csr_with_basic_constraints(path: &Path, subject_cn: &str, ca: bool) {
    use rand::rngs::OsRng;
    use x509_cert::builder::{Builder, RequestBuilder};
    use x509_cert::der::Encode;
    use x509_cert::ext::pkix::constraints::BasicConstraints;
    use x509_cert::name::Name;

    let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let subject = Name::from_str(&format!("CN={subject_cn}")).expect("valid subject");
    let mut builder = RequestBuilder::new(subject, &signing_key).expect("csr builder");
    builder
        .add_extension(&BasicConstraints {
            ca,
            path_len_constraint: None,
        })
        .expect("add basic constraints");
    let csr = builder
        .build::<p256::ecdsa::DerSignature>()
        .expect("build csr");
    std::fs::write(path, csr.to_der().expect("encode csr")).expect("write csr");
}

/// Read-only: safe to run against any connected device, production or not.
#[test]
fn get_ca_reads_connected_device_without_error() {
    let dir = TempDir::new();
    let args = GetCaArgs {
        serial: test_serial(),
        slot: SlotId::Signature,
        iopath: dir.path().to_path_buf(),
        filename: "hardware-test-get-ca".into(),
    };
    get_ca::run(&args).expect("get-ca should succeed against the pinned test device");
}

/// Destructive: generates a root CA key in `test_slot()` on the device pinned
/// by `YUBICA_TEST_SERIAL` and issues a host certificate from it. Requires
/// the test key's PIN/management key to already be rotated away from the
/// factory defaults (the CLI's own safety checks in `init_ca` enforce that,
/// same as in production use).
#[test]
fn init_ca_then_issue_host_round_trip() {
    let serial = test_serial();
    let pin = required_env("YUBICA_TEST_PIN");
    let mgm_key_hex = required_env("YUBICA_TEST_MGM_KEY_HEX");
    let dir = TempDir::new();

    let ca_args = InitCaArgs {
        serial,
        subject: "CN=YubiCA Hardware Test Root".into(),
        validity: ValidityArgs {
            valid_years: Some(1),
            valid_months: None,
            valid_days: None,
        },
        algorithm: CliAlgorithm::EccP256,
        pin_policy: CliPinPolicy::Never,
        touch_policy: CliTouchPolicy::Never,
        slot: test_slot(),
        mgm_key_hex: Some(mgm_key_hex),
        pin: PinArg {
            pin: Some(pin.clone()),
        },
        force: true,
    };
    init_ca::run(&ca_args).expect("init-ca should succeed against the disposable test key");

    let get_ca_args = GetCaArgs {
        serial,
        slot: test_slot(),
        iopath: dir.path().to_path_buf(),
        filename: "hardware-test-ca".into(),
    };
    get_ca::run(&get_ca_args).expect("get-ca should retrieve the freshly initialized root ca");
    assert!(dir.path().join("hardware-test-ca.crt").exists());

    let host_args = IssueHostArgs {
        serial,
        host: vec!["hardware-test.internal".into()],
        subject: None,
        validity: ValidityArgs {
            valid_years: None,
            valid_months: None,
            valid_days: Some(1),
        },
        algorithm: CliAlgorithm::EccP256,
        slot: test_slot(),
        pin: PinArg {
            pin: Some(pin.clone()),
        },
        passwd: None,
        crl_url: Vec::new(),
        iopath: dir.path().to_path_buf(),
        filename: "hardware-test-host".into(),
    };
    issue_host::run(&host_args)
        .expect("issue-host should succeed against the freshly initialized test CA");

    assert!(dir.path().join("hardware-test-host.crt").exists());
    assert!(dir.path().join("hardware-test-host.key").exists());
    assert!(dir.path().join("hardware-test-host.csr").exists());

    // A CSR that itself requests CA:TRUE must be refused unless --ca is passed
    // explicitly: whether a certificate is a CA is the signer's decision, not
    // the requester's (see `ensure_leaf_basic_constraints`).
    let ca_request_csr = dir.path().join("sign-test-ca-request.csr");
    write_csr_with_basic_constraints(&ca_request_csr, "Rogue Intermediate", true);

    let sign_without_ca = SignCsrArgs {
        serial,
        slot: test_slot(),
        validity: ValidityArgs {
            valid_years: None,
            valid_months: None,
            valid_days: Some(1),
        },
        pin: PinArg {
            pin: Some(pin.clone()),
        },
        ca: false,
        crl_url: vec!["http://ca.example.internal/root.crl".into()],
        iopath: dir.path().to_path_buf(),
        filename: "sign-test-ca-request".into(),
    };
    assert!(
        sign_csr::run(&sign_without_ca).is_err(),
        "sign-csr without --ca must refuse a csr that itself requests CA:TRUE"
    );
    assert!(
        !dir.path().join("sign-test-ca-request.crt").exists(),
        "a refused sign-csr must not leave a certificate file behind"
    );

    let sign_with_ca = SignCsrArgs {
        ca: true,
        ..sign_without_ca
    };
    sign_csr::run(&sign_with_ca)
        .expect("sign-csr --ca should sign the same csr as an intermediate");
    assert!(dir.path().join("sign-test-ca-request.crt").exists());

    // The same CSR machinery, but requesting CA:FALSE, must still work
    // without --ca (the guard only rejects CA-capable requests).
    let leaf_csr = dir.path().join("sign-test-leaf.csr");
    write_csr_with_basic_constraints(&leaf_csr, "Ordinary Leaf", false);

    let sign_leaf = SignCsrArgs {
        serial,
        slot: test_slot(),
        validity: ValidityArgs {
            valid_years: None,
            valid_months: None,
            valid_days: Some(1),
        },
        pin: PinArg {
            pin: Some(pin.clone()),
        },
        ca: false,
        crl_url: Vec::new(),
        iopath: dir.path().to_path_buf(),
        filename: "sign-test-leaf".into(),
    };
    sign_csr::run(&sign_leaf).expect("sign-csr without --ca should sign a non-ca csr");
    assert!(dir.path().join("sign-test-leaf.crt").exists());

    // gen-crl: revoke the intermediate signed above and confirm its serial
    // shows up in the resulting, YubiKey-signed CRL. Output files are PEM
    // (see `export_certificate_pem`/`gen_crl::run`), so decode that first.
    let issued_pem =
        std::fs::read(dir.path().join("sign-test-ca-request.crt")).expect("read issued cert");
    let (_, issued_der) = pem_rfc7468::decode_vec(&issued_pem).expect("decode issued cert pem");
    let issued_cert =
        x509_cert::Certificate::from_der(&issued_der).expect("parse issued intermediate cert");

    // --crl-url should have added a CRLDistributionPoints extension pointing
    // at the URL given to sign-csr above.
    {
        use const_oid::AssociatedOid;
        use x509_cert::ext::pkix::CrlDistributionPoints;
        use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};

        let crl_distribution_points = issued_cert
            .tbs_certificate
            .extensions
            .as_ref()
            .into_iter()
            .flatten()
            .find(|ext| ext.extn_id == CrlDistributionPoints::OID)
            .map(|ext| {
                CrlDistributionPoints::from_der(ext.extn_value.as_bytes())
                    .expect("decode crl distribution points")
            })
            .expect("sign-csr --crl-url should add a CRLDistributionPoints extension");

        let url = match &crl_distribution_points.0[0].distribution_point {
            Some(DistributionPointName::FullName(names)) => match &names[0] {
                GeneralName::UniformResourceIdentifier(uri) => uri.as_str(),
                other => panic!("expected a URI general name, got {other:?}"),
            },
            other => panic!("expected a fullName distribution point, got {other:?}"),
        };
        assert_eq!(url, "http://ca.example.internal/root.crl");
    }

    let revoked_serial_hex = hex::encode(issued_cert.tbs_certificate.serial_number.as_bytes());

    let revoked_list_path = dir.path().join("revoked-list.txt");
    std::fs::write(
        &revoked_list_path,
        format!("{revoked_serial_hex},2026-01-01,key-compromise\n"),
    )
    .expect("write revoked list");

    let gen_crl_args = GenCrlArgs {
        serial,
        slot: test_slot(),
        revoked: revoked_list_path,
        next_update_days: 7,
        crl_number: Some(1),
        pin: PinArg { pin: Some(pin) },
        iopath: dir.path().to_path_buf(),
        filename: "hardware-test".into(),
    };
    gen_crl::run(&gen_crl_args)
        .expect("gen-crl should sign a crl listing the revoked intermediate");

    let crl_pem = std::fs::read(dir.path().join("hardware-test.crl")).expect("read generated crl");
    let (_, crl_der) = pem_rfc7468::decode_vec(&crl_pem).expect("decode generated crl pem");
    let crl = x509_cert::crl::CertificateList::from_der(&crl_der).expect("parse generated crl");
    let revoked_certificates = crl
        .tbs_cert_list
        .revoked_certificates
        .expect("crl should list the revoked intermediate");
    assert_eq!(revoked_certificates.len(), 1);
    assert_eq!(
        revoked_certificates[0].serial_number.as_bytes(),
        issued_cert.tbs_certificate.serial_number.as_bytes()
    );
}
