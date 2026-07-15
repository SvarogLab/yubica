use yubikey::MgmKey;

use crate::error::AppError;

pub const FACTORY_DEFAULT_PIN: &str = "123456";

pub fn parse_management_key(input: Option<&str>) -> Result<(MgmKey, bool), AppError> {
    let mgm_key = match input {
        Some(value) => {
            let normalized: String = value
                .chars()
                .filter(|ch| !matches!(ch, ':' | '-' | ' '))
                .collect();

            let bytes = hex::decode(&normalized)
                .map_err(|err| AppError::InvalidManagementKeyHex(err.to_string()))?;

            MgmKey::from_bytes(bytes)
                .map_err(|err| AppError::InvalidManagementKeyHex(err.to_string()))?
        }
        None => MgmKey::default(),
    };

    let default_mgm_key = MgmKey::default();
    let uses_default = mgm_key.as_ref() == default_mgm_key.as_ref();

    Ok((mgm_key, uses_default))
}

pub fn ensure_non_default_management_key(uses_default_mgm_key: bool) -> Result<(), AppError> {
    if uses_default_mgm_key {
        return Err(AppError::FactoryDefaultManagementKey);
    }

    Ok(())
}

pub fn ensure_non_default_pin(pin: &str) -> Result<(), AppError> {
    if pin == FACTORY_DEFAULT_PIN {
        return Err(AppError::FactoryDefaultPin);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_input_uses_factory_default_key() {
        let (_, uses_default) = parse_management_key(None).unwrap();
        assert!(uses_default);
    }

    #[test]
    fn factory_default_hex_is_flagged_as_default() {
        let (_, uses_default) =
            parse_management_key(Some("010203040506070801020304050607080102030405060708")).unwrap();
        assert!(uses_default);
    }

    #[test]
    fn separators_are_normalized_before_decoding() {
        let plain =
            parse_management_key(Some("112233445566778811223344556677881122334455667788")).unwrap();
        let with_separators = parse_management_key(Some(
            "11:22:33:44:55:66:77:88-11 22:33:44:55:66:77:88-11:22:33:44:55:66:77:88",
        ))
        .unwrap();
        assert_eq!(plain.0.as_ref(), with_separators.0.as_ref());
        assert!(!plain.1);
    }

    #[test]
    fn invalid_hex_is_rejected() {
        let result = parse_management_key(Some("not-hex-zzzz"));
        assert!(result.is_err());
    }

    #[test]
    fn ensure_non_default_management_key_rejects_default() {
        assert!(ensure_non_default_management_key(true).is_err());
        assert!(ensure_non_default_management_key(false).is_ok());
    }

    #[test]
    fn ensure_non_default_pin_rejects_factory_pin() {
        assert!(ensure_non_default_pin("123456").is_err());
        assert!(ensure_non_default_pin("654321").is_ok());
    }
}
