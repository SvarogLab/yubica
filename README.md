# YubiCA

`yubica` is a Rust CLI for managing an offline root CA stored on a YubiKey PIV slot and for signing
certificates or CSRs without exposing the root private key.

The tool is designed for air-gapped or semi-air-gapped workflows where:

- the root CA key stays on the YubiKey
- intermediate or leaf CSRs are signed offline
- output files are written to an existing directory only

## Current capabilities

- List connected YubiKeys and their serial numbers
- List occupancy of common PIV slots
- Initialize a self-signed root CA on a YubiKey slot
- Retrieve the certificate from a YubiKey PIV slot
- Sign an existing CSR with a YubiKey-backed CA key
- Generate a host private key and CSR locally, then sign it with the YubiKey-backed CA

## Selecting a device

Every command except `list-keys` requires `--serial` (or `YUBICA_SERIAL`) to
pick which connected YubiKey to operate on. There is no "just use whichever
one is plugged in" fallback: with more than one device connected, an
unqualified open is ambiguous and this tool refuses to guess.

```powershell
yubica list-keys
yubica get-ca --serial 12345678 --iopath . --filename current-ca
```

## Logging

Use `--log` to control verbosity.

Supported values:

- `trace`
- `debug`
- `info`
- `warn`
- `error`

Examples:

```powershell
yubica --log info get-ca --serial 12345678
yubica --log debug list-slots --serial 12345678
```

If `--log` is provided, it takes priority over `RUST_LOG`.
If neither is set, the default level is `info`.

## Secrets

`--pin`, `--mgm-key-hex`, and `--passwd` can be passed as CLI flags, but that leaks
them into shell history and process listings. Prefer the environment variables
below; an explicit CLI flag still takes priority if both are set.

| Flag | Environment variable |
| --- | --- |
| `--pin` | `YUBICA_PIN` |
| `--mgm-key-hex` | `YUBICA_MGM_KEY_HEX` |
| `--passwd` | `YUBICA_PASSWD` |

```powershell
$env:YUBICA_PIN = "123456"
yubica sign-csr --serial 12345678 --iopath . --filename intermediate
```

## Output model

Commands that write files use:

- `--iopath` for the output directory
- `--filename` for the base filename

The directory must already exist. The tool does not create directories.

Generated extensions:

- certificate: `.crt`
- private key: `.key`
- CSR: `.csr`

Examples:

```powershell
yubica get-ca --serial 12345678 --iopath . --filename current-ca
yubica sign-csr --serial 12345678 --iopath . --filename intermediate
yubica issue-host --serial 12345678 --host app.example.internal --iopath . --filename app-example
```

## Validity arguments

The following flags are mutually exclusive:

- `--valid-days`
- `--valid-months`
- `--valid-years`

If none is provided, the command uses its default validity.

Current defaults:

- Root CA: `20` years
- CSR signing: `20` years
- Host certificate: `1` year

Examples:

```powershell
yubica init-ca --serial 12345678 --valid-years 20
yubica sign-csr --serial 12345678 --filename int --valid-days 7300
yubica issue-host --serial 12345678 --host api.example.internal --valid-months 6
```

## Commands

### `list-keys`

Enumerates connected PC/SC readers and reports the serial of any YubiKey found. This is the only
command that doesn't require `--serial`.

```powershell
yubica list-keys
```

### `list-slots`

Logs the occupancy state of common PIV slots.

```powershell
yubica list-slots --serial 12345678
```

### `init-ca`

Creates a self-signed root CA certificate backed by a private key generated inside the YubiKey.

```powershell
yubica init-ca --serial 12345678 --pin 654321 --mgm-key-hex 010203040506070801020304050607080102030405060708
```

Important notes:

- default slot is `9c`
- default subject is `CN=Offline Root CA`
- default algorithm is `ecc-p384`
- default PIN policy is `always`
- default touch policy is `always`
- `init-ca` always requires `--pin` so the current token PIN can be verified before key generation
- `init-ca` refuses to run with the factory default management key
- `init-ca` refuses to run with the factory default PIN (`123456`)
- `--algorithm`, `--pin-policy`, and `--touch-policy` are configurable
- the tool does not probe default PIN or PUK values on-device, because failed attempts would burn retry counters
- `--force` suppresses occupancy preflight, but it is not a full key deletion workflow
- `init-ca` does not write any files; use `get-ca` to export the resulting certificate
- the management key must be `TDES`: this tool only implements the 3DES challenge-response and
  cannot authenticate against an `AES128`/`AES192`/`AES256` management key at all. Firmware 5.7.x
  and later default a fresh device to `AES192`, so on such a device you must first force the
  algorithm back to TDES with `ykman piv access change-management-key -a tdes -n <new-key-hex>`
  before `init-ca` (or any other command using `--mgm-key-hex`) will authenticate successfully

### `get-ca`

Reads the certificate from a YubiKey PIV slot (the root CA slot, `9c`, by default) and exports it
if present.

```powershell
yubica get-ca --serial 12345678 --iopath . --filename current-ca
```

This produces:

- `current-ca.crt`

Notes:

- default slot is `9c`
- `--slot` reads a different slot, for example if the CA was initialized elsewhere
- if the slot holds no certificate, nothing is written and a message is logged

### `sign-csr`

Signs an existing CSR with the CA certificate/key from the selected YubiKey slot. The CSR is read
from `<iopath>/<filename>.csr`, so place it there under the same base name used for the output.

```powershell
yubica sign-csr --serial 12345678 --pin 123456 --iopath . --filename intermediate
```

Reads:

- `intermediate.csr`

Output:

- `intermediate.crt`

CSR handling:

- default slot is `9c`
- default validity is `20` years
- PEM and DER CSR input are supported
- requested extensions are partially propagated
- unsupported CSR extensions are ignored with a warning
- before signing (and before the YubiKey prompts for a touch), the CSR's subject and requested
  extensions are logged for review

Currently supported propagated CSR extensions:

- `BasicConstraints`
- `KeyUsage`
- `ExtendedKeyUsage`
- `SubjectAltName`

The tool also adds:

- `SubjectKeyIdentifier`
- `AuthorityKeyIdentifier`

Whether the issued certificate is a CA is the signer's decision, not the requester's: a CSR's own
`BasicConstraints`/`KeyUsage` are only ever a request, never an authorization. Pass `--ca` to sign
an intermediate: it forces `BasicConstraints` `CA:TRUE` and `KeyUsage` `keyCertSign`+`cRLSign` on
the issued certificate, ignoring whatever the CSR itself requested for those two extensions.
Without `--ca`, the command refuses to sign a CSR that itself requests `CA:TRUE` or
`keyCertSign`/`cRLSign` — it does not silently downgrade such a CSR to a leaf certificate. This
prevents any CSR from self-declaring CA authority through a plain `sign-csr` call.

```powershell
yubica sign-csr --serial 12345678 --ca --pin 123456 --iopath . --filename intermediate
```

A CA never issues a certificate that outlives itself: if the requested validity
would extend past the issuer certificate's own expiry, `not_after` is silently
clamped to the issuer's expiry (a warning is logged when this happens).

### `issue-host`

Generates a local host private key, creates a CSR, signs it with the YubiKey-backed CA, and writes all artifacts.

```powershell
yubica issue-host --serial 12345678 --host api.example.internal --host 10.10.10.20 --pin 123456 --iopath . --filename api-example
```

Output:

- `api-example.key`
- `api-example.csr`
- `api-example.crt`

The generated host CSR always requests `BasicConstraints` (`CA:FALSE`) and
`KeyUsage` (`digitalSignature`) in addition to the SAN/`serverAuth` EKU, so the
issued leaf certificate carries them regardless of what `sign-csr`'s generic
CSR-extension propagation would otherwise include.

If `--passwd` is provided, the generated private key is written as encrypted PKCS#8 PEM.

```powershell
yubica issue-host --serial 12345678 --host api.example.internal --pin 123456 --passwd changeit --iopath . --filename api-example
```

## Air-gapped OpenBao intermediate flow

When OpenBao generates an intermediate key internally, the private key never leaves Bao. In that
workflow the offline root only needs to sign the CSR.

Typical flow:

1. Generate the intermediate CSR inside OpenBao
2. Save the CSR as `<filename>.csr` in the directory you'll pass as `--iopath`, for example
   `intermediate.csr`
3. Sign it offline with `yubica sign-csr --ca` — OpenBao's own CSR does not reliably request
   `BasicConstraints`/`KeyUsage`, and without `--ca` the issued certificate would be a plain leaf,
   which OpenBao then refuses to import as an intermediate ("Refusing to import non-CA
   certificate")
4. Paste or upload the resulting `intermediate.crt` back into OpenBao
5. Concatenate the signed intermediate certificate and root certificate if your `set-signed`
   workflow expects a certificate chain

Example offline signing step:

```powershell
yubica sign-csr --serial 12345678 --ca --pin 123456 --iopath . --filename intermediate
```

## Security notes

- Only ECC (`ecc-p256`, `ecc-p384`) is supported; RSA was removed. This also sidesteps the
  RustCrypto `rsa` crate's unpatched Marvin timing-sidechannel advisory (RUSTSEC-2023-0071), which
  no longer applies since the crate isn't a dependency
- Prefer `YUBICA_PIN`/`YUBICA_MGM_KEY_HEX`/`YUBICA_PASSWD` over the equivalent CLI flags to avoid
  leaking secrets into shell history and process listings
- The root private key stays on the YubiKey for `init-ca` and `sign-csr`
- `issue-host` intentionally generates the host private key locally, not on the YubiKey
- Factory default management keys should not be kept in production workflows
- Factory default PINs must be rotated before `init-ca`; the CLI refuses default management keys
  and rejects the default PIN
- Every command except `list-keys` requires an explicit `--serial`; the tool never guesses which
  connected YubiKey to use
- This repository currently does not implement a complete slot cleanup or key deletion workflow
  for replacing an existing CA in-place

## Testing

`cargo test` runs the unit test suite (pure logic: validity/calendar math, CSR
subject/SAN handling, management-key parsing, OID-based algorithm detection,
output-path validation). No hardware is touched and nothing here requires a
connected YubiKey.

A separate suite in `tests/hardware.rs` exercises real hardware end-to-end
(`list-keys`-style enumeration is not covered there, but `get-ca`, `init-ca`,
and `issue-host` are). It never runs by default:

```powershell
$env:YUBICA_TEST_SERIAL = "12345678"     # required: every test needs this
$env:YUBICA_TEST_PIN = "..."             # required: only for the destructive test
$env:YUBICA_TEST_MGM_KEY_HEX = "..."     # required: only for the destructive test
$env:YUBICA_TEST_SLOT = "9c"             # optional, defaults to 9c

cargo test --features hardware-tests --test hardware -- --test-threads=1
```

Notes:

- Use a disposable YubiKey. `init_ca_then_issue_host_round_trip` generates a
  real key pair in the chosen slot with `--force`, permanently overwriting
  whatever was there.
- The test key's PIN and management key must already be rotated away from
  the factory defaults — `init-ca`'s own safety checks enforce that same as
  in production. On firmware 5.7.x+ this also means forcing the management
  key algorithm back to `TDES` (see the `init-ca` section above for why).
- `--test-threads=1` is required. PC/SC does not tolerate two tests opening
  the same physical smart card concurrently (the default parallel test
  runner will otherwise fail with a `ResetCard` PC/SC error).
- There's no extra opt-in flag beyond the cargo feature and the environment
  variables above — specifying a real device serial and its real secrets
  already is the deliberate step that makes this safe to trust.

## Examples summary

```powershell
yubica list-keys

yubica list-slots --serial 12345678

yubica init-ca --serial 12345678 --pin 654321 --mgm-key-hex 010203040506070801020304050607080102030405060708

yubica get-ca --serial 12345678 --iopath . --filename current-ca

yubica sign-csr --serial 12345678 --ca --pin 123456 --iopath . --filename intermediate

yubica issue-host --serial 12345678 --host app.example.internal --host 10.0.0.10 --pin 123456 --iopath . --filename app
```
