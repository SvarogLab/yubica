use tracing::info;

use crate::{
    cli::ListSlotsArgs,
    defaults::SlotsDefaults,
    error::AppError,
    hardware::device::{open_yubikey, print_device_info, read_slot_certificate},
};

pub fn run(args: &ListSlotsArgs) -> Result<(), AppError> {
    let mut yubikey = open_yubikey(args.serial)?;
    print_device_info(&mut yubikey);

    for slot in SlotsDefaults::SLOTS {
        let present = read_slot_certificate(&mut yubikey, slot).is_some();
        info!(slot = %slot, present, "slot state");
    }

    Ok(())
}
