use tracing::{info, warn};
use yubikey::reader::Context;

use crate::{cli::ListKeysArgs, error::AppError};

/// Enumerates connected PC/SC readers and reports the serial of any YubiKey
/// found, so an operator can pick the right `--serial` for every other
/// command without guessing when more than one device is plugged in.
pub fn run(_: &ListKeysArgs) -> Result<(), AppError> {
    let mut context = Context::open()?;
    let mut found = 0usize;

    for reader in context.iter()? {
        match reader.open() {
            Ok(yubikey) => {
                found += 1;
                info!(
                    reader = %reader.name(),
                    serial = %yubikey.serial(),
                    version = ?yubikey.version(),
                    "connected yubikey"
                );
            }
            Err(err) => {
                warn!(
                    reader = %reader.name(),
                    error = ?err,
                    "reader present but could not be opened as a YubiKey"
                );
            }
        }
    }

    if found == 0 {
        info!("no YubiKeys detected");
    }

    Ok(())
}
