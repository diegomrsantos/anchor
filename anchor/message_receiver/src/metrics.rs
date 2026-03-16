use std::sync::LazyLock;

pub use metrics::*;

pub static MESSAGE_RECEIVER_INTEREST_CHECK_TIME: LazyLock<Result<Histogram>> =
    LazyLock::new(|| {
        try_create_histogram(
            "anchor_message_receiver_interest_check_seconds",
            "Time spent performing message receiver interest checks",
        )
    });
