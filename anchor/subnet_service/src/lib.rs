//! Subnet service for SSV network topology.
//!
//! This crate provides:
//! - Subnet identification and calculation algorithms (`SubnetId`)
//! - Background service for managing subnet subscriptions
//! - Message rate calculation for gossipsub topic scoring
//! - Fork-aware routing for subnet topology transitions

pub mod message_rate;
pub mod routing;
mod scoring;
mod service;
mod subnet;

pub use routing::{
    FORK_PREPARATION_EPOCHS, ForkSet, SubnetRouter, accept_forks, calculate_subnet_for_committee,
    current_epoch, process_forks, publish_fork, subscribe_forks,
};
pub use scoring::{calculate_message_rate_for_subnet, get_committee_info_for_subnet};
pub use service::start_subnet_service;
pub use subnet::{
    SUBNET_COUNT, SUBNET_COUNT_NZ, SubnetBits, SubnetCalculationError, SubnetEvent, SubnetId,
};
