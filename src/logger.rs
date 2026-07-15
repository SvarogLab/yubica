use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::cli::LogLevel;

pub fn init(level: LogLevel, cli_overrides_env: bool) {
    let env_filter = if cli_overrides_env {
        EnvFilter::new(level.as_filter())
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
    };

    let _ = tracing_subscriber::registry()
        .with(env_filter)
        .with(
            fmt::layer()
                .with_target(false)
                .with_thread_ids(false)
                .with_thread_names(false)
                .compact(),
        )
        .try_init();
}
