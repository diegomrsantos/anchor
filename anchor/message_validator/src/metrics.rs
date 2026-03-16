use std::sync::LazyLock;

pub use metrics::*;

pub static MESSAGE_VALIDATOR_LOOKUP_TIME: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram(
        "anchor_message_validator_lookup_seconds",
        "Time spent on validator DB-backed committee and operator lookups",
    )
});
