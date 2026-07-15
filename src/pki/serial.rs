use rand::{RngCore, rngs::OsRng};
use x509_cert::serial_number::SerialNumber;

use crate::error::AppError;

pub fn generate_serial_number() -> Result<SerialNumber, AppError> {
    let mut serial_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut serial_bytes);
    serial_bytes[0] &= 0x7f;
    if serial_bytes[0] == 0 {
        serial_bytes[0] = 1;
    }

    Ok(SerialNumber::new(&serial_bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_number_is_16_bytes_with_positive_leading_byte() {
        let serial = generate_serial_number().unwrap();
        let bytes = serial.as_bytes();
        assert_eq!(bytes.len(), 16);
        assert_eq!(
            bytes[0] & 0x80,
            0,
            "leading bit must be clear (positive DER INTEGER)"
        );
        assert_ne!(bytes[0], 0, "leading byte must not be zero");
    }

    #[test]
    fn serial_numbers_are_not_predictable() {
        let a = generate_serial_number().unwrap();
        let b = generate_serial_number().unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }
}
