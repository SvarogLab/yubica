use std::time::{Duration, SystemTime};

use x509_cert::{
    der::{
        DateTime,
        asn1::{GeneralizedTime, UtcTime},
    },
    time::{Time, Validity},
};

use crate::error::AppError;

pub fn build_validity(
    valid_years: Option<u16>,
    valid_months: Option<u16>,
    valid_days: Option<u32>,
    default_years: u16,
) -> Result<Validity, AppError> {
    if let Some(valid_days) = valid_days {
        return Ok(Validity::from_now(Duration::from_secs(
            u64::from(valid_days) * 24 * 60 * 60,
        ))?);
    }

    let not_before = Time::try_from(SystemTime::now())?;
    let not_after_date_time = if let Some(valid_months) = valid_months {
        add_calendar_months(not_before.to_date_time(), valid_months)?
    } else {
        add_calendar_years(
            not_before.to_date_time(),
            valid_years.unwrap_or(default_years),
        )?
    };
    let not_after = if not_after_date_time.year() <= UtcTime::MAX_YEAR {
        Time::from(UtcTime::from_date_time(not_after_date_time)?)
    } else {
        Time::from(GeneralizedTime::from_date_time(not_after_date_time))
    };

    Ok(Validity {
        not_before,
        not_after,
    })
}

fn add_calendar_years(date_time: DateTime, years: u16) -> Result<DateTime, AppError> {
    let target_year = date_time.year() + years;
    let mut day = date_time.day();

    loop {
        if let Ok(adjusted) = DateTime::new(
            target_year,
            date_time.month(),
            day,
            date_time.hour(),
            date_time.minutes(),
            date_time.seconds(),
        ) {
            return Ok(adjusted);
        }

        if day == 1 {
            return Err(AppError::InvalidValidityYears(years));
        }

        day -= 1;
    }
}

fn add_calendar_months(date_time: DateTime, months: u16) -> Result<DateTime, AppError> {
    let total_months = u32::from(date_time.month()) - 1 + u32::from(months);
    let target_year = date_time.year() + (total_months / 12) as u16;
    let target_month = (total_months % 12) as u8 + 1;
    let mut day = date_time.day();

    loop {
        if let Ok(adjusted) = DateTime::new(
            target_year,
            target_month,
            day,
            date_time.hour(),
            date_time.minutes(),
            date_time.seconds(),
        ) {
            return Ok(adjusted);
        }

        if day == 1 {
            return Err(AppError::InvalidValidityMonths(months));
        }

        day -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_validity_from_days_spans_requested_duration() {
        let validity = build_validity(None, None, Some(30), 20).unwrap();
        let elapsed = validity.not_after.to_date_time().unix_duration().as_secs()
            - validity.not_before.to_date_time().unix_duration().as_secs();
        assert_eq!(elapsed, 30 * 24 * 60 * 60);
    }

    #[test]
    fn build_validity_falls_back_to_default_years() {
        let validity = build_validity(None, None, None, 5).unwrap();
        let before = validity.not_before.to_date_time();
        let after = validity.not_after.to_date_time();
        assert_eq!(after.year(), before.year() + 5);
        assert_eq!(after.month(), before.month());
        assert_eq!(after.day(), before.day());
    }

    #[test]
    fn add_calendar_years_clamps_leap_day() {
        // 2024-02-29 + 1 year -> 2025 is not a leap year, so day clamps to 28.
        let leap_day = DateTime::new(2024, 2, 29, 12, 0, 0).unwrap();
        let adjusted = add_calendar_years(leap_day, 1).unwrap();
        assert_eq!(
            (adjusted.year(), adjusted.month(), adjusted.day()),
            (2025, 2, 28)
        );
    }

    #[test]
    fn add_calendar_months_wraps_year_and_clamps_day() {
        // 2023-10-31 + 4 months -> 2024-02, a leap year, so day clamps to 29 (not 28).
        let start = DateTime::new(2023, 10, 31, 0, 0, 0).unwrap();
        let adjusted = add_calendar_months(start, 4).unwrap();
        assert_eq!(
            (adjusted.year(), adjusted.month(), adjusted.day()),
            (2024, 2, 29)
        );
    }

    #[test]
    fn add_calendar_months_handles_short_month_without_wrap() {
        // 2023-01-31 + 1 month -> 2023-02 has 28 days.
        let start = DateTime::new(2023, 1, 31, 0, 0, 0).unwrap();
        let adjusted = add_calendar_months(start, 1).unwrap();
        assert_eq!(
            (adjusted.year(), adjusted.month(), adjusted.day()),
            (2023, 2, 28)
        );
    }
}
