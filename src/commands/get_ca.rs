use tracing::info;

use crate::{
    cli::GetCaArgs,
    error::AppError,
    hardware::device::{
        export_certificate_pem, open_yubikey, print_certificate_details, print_device_info,
        read_slot_certificate,
    },
    io::OutputPlan,
};

pub fn run(args: &GetCaArgs) -> Result<(), AppError> {
    let mut yubikey = open_yubikey(args.serial)?;
    let output = OutputPlan::new(&args.iopath, &args.filename)?;

    print_device_info(&mut yubikey);

    match read_slot_certificate(&mut yubikey, args.slot) {
        Some(cert) => {
            print_certificate_details(args.slot, &cert);
            export_certificate_pem(&cert, &output.crt_path())?;
            info!(path = %output.crt_path().display(), "exported ca certificate");
        }
        None => info!(slot = %args.slot, "no readable certificate found in slot"),
    }

    Ok(())
}
