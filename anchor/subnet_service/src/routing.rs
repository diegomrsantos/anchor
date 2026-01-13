//! Centralized routing policy for subnet topology fork transition.
//!
//! This module provides a single source of truth for fork-related routing decisions,
//! answering four key questions:
//! 1. Which fork's topology to publish with? → `publish_fork()`
//! 2. Which forks to subscribe to? → `subscribe_forks()`
//! 3. Which forks to accept messages from (gossipsub)? → `accept_forks()`
//! 4. Which forks to process messages for? → `process_forks()`
//!
//! ## Fork Timeline (SIP-43 Compliant)
//!
//! Let F = fork_epoch (Boole), P = FORK_PREPARATION_EPOCHS:
//!
//! | Epoch | Subscribe          | Publish | Accept (gossipsub) | Process        |
//! |-------|--------------------|---------|--------------------|----------------|
//! | F-P-1 | {Alan}             | Alan    | {Alan}             | {Alan}         |
//! | F-P   | {Alan, Boole}      | Alan    | {Alan, Boole}      | {Alan}         |
//! | ...   | {Alan, Boole}      | Alan    | {Alan, Boole}      | {Alan}         |
//! | F-1   | {Alan, Boole}      | Alan    | {Alan, Boole}      | {Alan}         |
//! | F     | {Boole}            | Boole   | {Boole}            | {Boole}        |
//! | F+1   | {Boole}            | Boole   | {Boole}            | {Boole}        |
//!
//! Key behaviors per SIP-43:
//! - **FORK_PREPARATION_EPOCHS**: Start dual-subscribing P epochs before fork
//! - **Accept during pre-subscribe**: Accept Boole messages for gossipsub propagation
//! - **Don't process pre-fork**: Only process Alan messages until fork epoch
//! - **Immediate cutoff at fork**: No grace period after fork

use std::num::NonZeroU64;

use database::{NetworkState, NonUniqueIndex};
pub use fork::{FORK_PREPARATION_EPOCHS, Fork, ForkSchedule};
use slot_clock::SlotClock;
use ssv_types::{CommitteeId, OperatorId};
use tokio::sync::watch;
use types::Epoch;

use crate::{SubnetCalculationError, SubnetId};

/// Fixed-size fork list with an explicit active length.
///
/// This keeps routing decisions allocation-free while still allowing dual-fork
/// transitions during fork windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkSet {
    len: usize,
    forks: [Fork; 2],
}

impl ForkSet {
    /// Max supported forks in a single decision window.
    pub const MAX_LEN: usize = 2;

    /// Alan-only fork set (pre-fork default).
    pub const fn alan_only() -> Self {
        Self {
            len: 1,
            forks: [Fork::Alan, Fork::Alan],
        }
    }

    /// Boole-only fork set (post-fork).
    pub const fn boole_only() -> Self {
        Self {
            len: 1,
            forks: [Fork::Boole, Fork::Boole],
        }
    }

    /// Dual-fork set used during the pre-subscribe window.
    pub const fn alan_and_boole() -> Self {
        Self {
            len: 2,
            forks: [Fork::Alan, Fork::Boole],
        }
    }

    /// Number of active forks.
    pub fn len(&self) -> usize {
        self.len
    }

    /// True when no forks are active.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Active fork slice (length is `len()`).
    pub fn as_slice(&self) -> &[Fork] {
        &self.forks[..self.len]
    }

    /// Iterate active forks.
    pub fn iter(&self) -> std::slice::Iter<'_, Fork> {
        self.as_slice().iter()
    }

    /// True when the fork is part of this set.
    pub fn contains(&self, fork: Fork) -> bool {
        self.iter().any(|f| *f == fork)
    }
}

/// Calculate the epoch when dual-subscription should start.
fn subscribe_transition_epoch(schedule: &ForkSchedule) -> Option<Epoch> {
    schedule
        .fork_epoch(Fork::Boole)
        .map(|fe| Epoch::new(fe.as_u64().saturating_sub(FORK_PREPARATION_EPOCHS)))
}

/// Determine which fork's topology to use for PUBLISHING messages at the given epoch.
///
/// # Decision Logic
///
/// - Before fork_epoch: Alan (committee_id % 128)
/// - At or after fork_epoch: Boole (MinHash topology)
/// - If Boole is not scheduled: always Alan
pub fn publish_fork(epoch: Epoch, schedule: &ForkSchedule) -> Fork {
    schedule.active_fork(epoch)
}

/// Determine which forks to SUBSCRIBE to at the given epoch.
///
/// Returns a `ForkSet` with up to 2 forks to avoid heap allocation while
/// supporting dual-subscription during the transition period.
///
/// # Decision Logic (SIP-43)
///
/// - Before (fork_epoch - FORK_PREPARATION_EPOCHS): {Alan}
/// - From (fork_epoch - FORK_PREPARATION_EPOCHS) to fork_epoch (exclusive): {Alan, Boole}
/// - At or after fork_epoch: {Boole}
/// - If Boole is not scheduled: always {Alan}
pub fn subscribe_forks(epoch: Epoch, schedule: &ForkSchedule) -> ForkSet {
    match schedule.fork_epoch(Fork::Boole) {
        None => ForkSet::alan_only(),
        Some(fork_epoch) => {
            let subscribe_start = subscribe_transition_epoch(schedule);

            match subscribe_start {
                Some(start) if epoch < start => {
                    // Before pre-subscribe window: only Alan
                    ForkSet::alan_only()
                }
                Some(_) if epoch < fork_epoch => {
                    // Pre-subscribe window: dual-subscribe
                    ForkSet::alan_and_boole()
                }
                _ => {
                    // At or after fork: only Boole
                    ForkSet::boole_only()
                }
            }
        }
    }
}

/// Determine which forks to ACCEPT messages from at the given epoch.
///
/// # Decision Logic (SIP-43)
///
/// - Before (fork_epoch - FORK_PREPARATION_EPOCHS): {Alan}
/// - From (fork_epoch - FORK_PREPARATION_EPOCHS) to fork_epoch (exclusive): {Alan, Boole}
/// - At or after fork_epoch: {Boole}
/// - If Boole is not scheduled: always {Alan}
///
/// **Important**: During pre-subscribe (F-2, F-1), nodes accept both Alan and Boole
/// messages for gossipsub propagation to warm up the mesh, but only process Alan.
pub fn accept_forks(epoch: Epoch, schedule: &ForkSchedule) -> ForkSet {
    // Accept follows the same logic as subscribe
    subscribe_forks(epoch, schedule)
}

/// Determine which forks to PROCESS messages for at the given epoch.
///
/// # Decision Logic (SIP-43)
///
/// - Before fork_epoch: {Alan} only (even during pre-subscribe window)
/// - At or after fork_epoch: {Boole}
/// - If Boole is not scheduled: always {Alan}
///
/// **Important**: During pre-subscribe (F-2, F-1), Boole messages are accepted
/// for gossipsub propagation but should NOT be processed for committee work.
pub fn process_forks(epoch: Epoch, schedule: &ForkSchedule) -> ForkSet {
    match schedule.fork_epoch(Fork::Boole) {
        None => ForkSet::alan_only(),
        Some(fork_epoch) => {
            if epoch < fork_epoch {
                // Before fork (including pre-subscribe window): only process Alan
                ForkSet::alan_only()
            } else {
                // At or after fork: process Boole
                ForkSet::boole_only()
            }
        }
    }
}

/// Consistency helper for computing the current epoch from a slot clock.
///
/// This ensures all components (subnet_service, message_sender, message_validator)
/// compute epoch the same way, preventing subtle inconsistencies during transition.
///
/// # Returns
///
/// - `Some(epoch)` if the slot clock returns a valid current slot
/// - `None` if the slot clock cannot determine the current slot (e.g., before genesis)
pub fn current_epoch(slot_clock: &impl SlotClock, slots_per_epoch: u64) -> Option<Epoch> {
    slot_clock.now().map(|slot| slot.epoch(slots_per_epoch))
}

/// Calculate subnet for a committee using the specified fork's algorithm.
pub fn calculate_subnet_for_committee(
    committee_id: CommitteeId,
    network_state: &NetworkState,
    subnet_count: NonZeroU64,
    fork: Fork,
) -> Result<SubnetId, SubnetCalculationError> {
    match fork {
        Fork::Alan => SubnetId::from_committee_alan(committee_id, subnet_count),
        Fork::Boole => {
            // Get operators for this committee
            let operators: Vec<OperatorId> = network_state
                .clusters()
                .get_all_by(&committee_id)
                .next()
                .map(|cluster| cluster.cluster_members.iter().copied().collect())
                .unwrap_or_default();

            SubnetId::from_operators(&operators, subnet_count)
        }
    }
}

/// Centralized router for subnet-related fork decisions.
///
/// This struct combines the fork schedule with runtime state (slot clock, network state)
/// to provide convenient methods for common routing operations.
pub struct SubnetRouter<S: SlotClock> {
    network_state_rx: watch::Receiver<NetworkState>,
    fork_schedule: ForkSchedule,
    slot_clock: S,
    slots_per_epoch: u64,
    subnet_count: NonZeroU64,
}

impl<S: SlotClock> SubnetRouter<S> {
    /// Create a new SubnetRouter.
    pub fn new(
        network_state_rx: watch::Receiver<NetworkState>,
        fork_schedule: ForkSchedule,
        slot_clock: S,
        slots_per_epoch: u64,
        subnet_count: NonZeroU64,
    ) -> Self {
        Self {
            network_state_rx,
            fork_schedule,
            slot_clock,
            slots_per_epoch,
            subnet_count,
        }
    }

    /// Get the subnet to publish to for this committee.
    ///
    /// Uses `publish_fork()` to determine Alan vs Boole based on current epoch.
    pub fn publish_subnet(
        &self,
        committee_id: CommitteeId,
    ) -> Result<SubnetId, SubnetCalculationError> {
        let epoch = current_epoch(&self.slot_clock, self.slots_per_epoch);
        let fork = epoch
            .map(|e| publish_fork(e, &self.fork_schedule))
            .unwrap_or(Fork::Alan);

        calculate_subnet_for_committee(
            committee_id,
            &self.network_state_rx.borrow(),
            self.subnet_count,
            fork,
        )
    }

    /// Validate that a message arrived on the correct subnet for this committee.
    ///
    /// Checks against all accepted forks at the current epoch. Returns the
    /// matched fork if valid, or an error if no fork matches.
    ///
    /// During the pre-subscribe window (F-2, F-1), both Alan and Boole
    /// subnets are accepted for gossipsub propagation.
    pub fn validate_subnet(
        &self,
        committee_id: CommitteeId,
        operators: &[OperatorId],
        received_subnet: SubnetId,
    ) -> Result<Fork, SubnetCalculationError> {
        let epoch = current_epoch(&self.slot_clock, self.slots_per_epoch);
        let fork_set = if let Some(e) = epoch {
            accept_forks(e, &self.fork_schedule)
        } else {
            ForkSet::alan_only()
        };

        for fork in fork_set.iter() {
            // Calculate expected subnet for this fork, skipping on error to try other forks.
            // This ensures a Boole error (e.g., EmptyOperatorList) doesn't reject valid
            // Alan messages during the dual-subscribe window.
            let expected_subnet = match fork {
                Fork::Alan => {
                    match SubnetId::from_committee_alan(committee_id, self.subnet_count) {
                        Ok(subnet) => subnet,
                        Err(_) => continue,
                    }
                }
                Fork::Boole => match SubnetId::from_operators(operators, self.subnet_count) {
                    Ok(subnet) => subnet,
                    Err(_) => continue,
                },
            };

            if expected_subnet == received_subnet {
                return Ok(*fork);
            }
        }

        Err(SubnetCalculationError::IncorrectTopic)
    }

    /// Check if a message with the given matched fork should be processed.
    ///
    /// During the pre-subscribe window (F-2, F-1), Boole messages are accepted
    /// for gossipsub propagation but should NOT be processed for committee work.
    /// Only messages matching `process_forks()` should be processed.
    pub fn should_process(&self, matched_fork: Fork) -> bool {
        let epoch = current_epoch(&self.slot_clock, self.slots_per_epoch);
        let fork_set = if let Some(e) = epoch {
            process_forks(e, &self.fork_schedule)
        } else {
            // Before genesis: only process Alan
            ForkSet::alan_only()
        };

        fork_set.contains(matched_fork)
    }

    /// Get subnets to subscribe to for a committee at the current epoch.
    ///
    /// During the pre-subscribe window, returns both Alan and Boole subnets.
    pub fn subscribe_subnets(
        &self,
        committee_id: CommitteeId,
    ) -> Result<Vec<SubnetId>, SubnetCalculationError> {
        let epoch = current_epoch(&self.slot_clock, self.slots_per_epoch);
        let fork_set = if let Some(e) = epoch {
            subscribe_forks(e, &self.fork_schedule)
        } else {
            ForkSet::alan_only()
        };

        let network_state = self.network_state_rx.borrow();
        let mut subnets = Vec::with_capacity(fork_set.len());

        for fork in fork_set.iter() {
            if let Ok(subnet) = calculate_subnet_for_committee(
                committee_id,
                &network_state,
                self.subnet_count,
                *fork,
            ) {
                // Avoid duplicates (Alan and Boole might map to same subnet)
                if !subnets.contains(&subnet) {
                    subnets.push(subnet);
                }
            }
        }

        if subnets.is_empty() {
            Err(SubnetCalculationError::EmptyOperatorList)
        } else {
            Ok(subnets)
        }
    }

    /// Get the fork schedule.
    pub fn fork_schedule(&self) -> &ForkSchedule {
        &self.fork_schedule
    }

    /// Get the subnet count.
    pub fn subnet_count(&self) -> NonZeroU64 {
        self.subnet_count
    }

    /// Get slots per epoch.
    pub fn slots_per_epoch(&self) -> u64 {
        self.slots_per_epoch
    }

    /// Borrow the network state.
    pub fn network_state(&self) -> watch::Ref<'_, NetworkState> {
        self.network_state_rx.borrow()
    }

    /// Get a reference to the slot clock.
    pub fn slot_clock(&self) -> &S {
        &self.slot_clock
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FORK_EPOCH: u64 = 100;

    fn schedule_with_boole(epoch: u64) -> ForkSchedule {
        let mut schedule = ForkSchedule::new();
        schedule.set_fork_epoch(Fork::Boole, Epoch::new(epoch));
        schedule
    }

    #[test]
    fn test_alan_forever() {
        let schedule = ForkSchedule::new(); // No Boole scheduled

        // Test various epochs
        for epoch_val in [0, 50, 100, 200, 1000] {
            let epoch = Epoch::new(epoch_val);

            assert_eq!(publish_fork(epoch, &schedule), Fork::Alan);

            let forks = subscribe_forks(epoch, &schedule);
            assert_eq!(forks.len(), 1);
            assert_eq!(forks.as_slice()[0], Fork::Alan);

            let forks = accept_forks(epoch, &schedule);
            assert_eq!(forks.len(), 1);
            assert_eq!(forks.as_slice()[0], Fork::Alan);

            let forks = process_forks(epoch, &schedule);
            assert_eq!(forks.len(), 1);
            assert_eq!(forks.as_slice()[0], Fork::Alan);
        }
    }

    #[test]
    fn test_publish_fork_timeline() {
        let schedule = schedule_with_boole(FORK_EPOCH);

        // Before fork
        assert_eq!(publish_fork(Epoch::new(97), &schedule), Fork::Alan);
        assert_eq!(publish_fork(Epoch::new(98), &schedule), Fork::Alan);
        assert_eq!(publish_fork(Epoch::new(99), &schedule), Fork::Alan);

        // At fork and after
        assert_eq!(publish_fork(Epoch::new(FORK_EPOCH), &schedule), Fork::Boole);
        assert_eq!(publish_fork(Epoch::new(101), &schedule), Fork::Boole);
        assert_eq!(publish_fork(Epoch::new(200), &schedule), Fork::Boole);
    }

    #[test]
    fn test_subscribe_forks_timeline() {
        let schedule = schedule_with_boole(FORK_EPOCH);
        let prep_start = FORK_EPOCH - FORK_PREPARATION_EPOCHS;

        // Before pre-subscribe window
        let forks = subscribe_forks(Epoch::new(prep_start - 1), &schedule);
        assert_eq!(forks.len(), 1);
        assert_eq!(forks.as_slice()[0], Fork::Alan);

        // Pre-subscribe window start: dual-subscribe
        let forks = subscribe_forks(Epoch::new(prep_start), &schedule);
        assert_eq!(forks.len(), 2);
        assert_eq!(forks.as_slice()[0], Fork::Alan);
        assert_eq!(forks.as_slice()[1], Fork::Boole);

        // Pre-subscribe window (F-1): still dual-subscribe
        let forks = subscribe_forks(Epoch::new(FORK_EPOCH - 1), &schedule);
        assert_eq!(forks.len(), 2);
        assert_eq!(forks.as_slice()[0], Fork::Alan);
        assert_eq!(forks.as_slice()[1], Fork::Boole);

        // At fork (F): only Boole
        let forks = subscribe_forks(Epoch::new(FORK_EPOCH), &schedule);
        assert_eq!(forks.len(), 1);
        assert_eq!(forks.as_slice()[0], Fork::Boole);

        // After fork (F+1): only Boole
        let forks = subscribe_forks(Epoch::new(FORK_EPOCH + 1), &schedule);
        assert_eq!(forks.len(), 1);
        assert_eq!(forks.as_slice()[0], Fork::Boole);
    }

    #[test]
    fn test_accept_forks_timeline() {
        let schedule = schedule_with_boole(FORK_EPOCH);
        let prep_start = FORK_EPOCH - FORK_PREPARATION_EPOCHS;

        // Before pre-subscribe window: only Alan
        let forks = accept_forks(Epoch::new(prep_start - 1), &schedule);
        assert_eq!(forks.len(), 1);
        assert_eq!(forks.as_slice()[0], Fork::Alan);

        // Pre-subscribe window start: accept both for propagation
        let forks = accept_forks(Epoch::new(prep_start), &schedule);
        assert_eq!(forks.len(), 2);
        assert_eq!(forks.as_slice()[0], Fork::Alan);
        assert_eq!(forks.as_slice()[1], Fork::Boole);

        // Pre-subscribe window (F-1): still accept both
        let forks = accept_forks(Epoch::new(FORK_EPOCH - 1), &schedule);
        assert_eq!(forks.len(), 2);
        assert_eq!(forks.as_slice()[0], Fork::Alan);
        assert_eq!(forks.as_slice()[1], Fork::Boole);

        // At fork (F): only Boole
        let forks = accept_forks(Epoch::new(FORK_EPOCH), &schedule);
        assert_eq!(forks.len(), 1);
        assert_eq!(forks.as_slice()[0], Fork::Boole);

        // After fork (F+1): only Boole
        let forks = accept_forks(Epoch::new(FORK_EPOCH + 1), &schedule);
        assert_eq!(forks.len(), 1);
        assert_eq!(forks.as_slice()[0], Fork::Boole);
    }

    #[test]
    fn test_process_forks_timeline() {
        let schedule = schedule_with_boole(FORK_EPOCH);

        // Before fork (including pre-subscribe window): only process Alan
        let forks = process_forks(Epoch::new(97), &schedule);
        assert_eq!(forks.len(), 1);
        assert_eq!(forks.as_slice()[0], Fork::Alan);

        let forks = process_forks(Epoch::new(98), &schedule);
        assert_eq!(forks.len(), 1);
        assert_eq!(forks.as_slice()[0], Fork::Alan);

        let forks = process_forks(Epoch::new(99), &schedule);
        assert_eq!(forks.len(), 1);
        assert_eq!(forks.as_slice()[0], Fork::Alan);

        // At fork (F): process Boole
        let forks = process_forks(Epoch::new(FORK_EPOCH), &schedule);
        assert_eq!(forks.len(), 1);
        assert_eq!(forks.as_slice()[0], Fork::Boole);

        // After fork (F+1): process Boole
        let forks = process_forks(Epoch::new(101), &schedule);
        assert_eq!(forks.len(), 1);
        assert_eq!(forks.as_slice()[0], Fork::Boole);
    }

    #[test]
    fn test_node_starts_after_fork() {
        let schedule = schedule_with_boole(FORK_EPOCH);

        // Node starts at epoch 200 (long after fork)
        let epoch = Epoch::new(200);

        assert_eq!(publish_fork(epoch, &schedule), Fork::Boole);

        let forks = subscribe_forks(epoch, &schedule);
        assert_eq!(forks.len(), 1);
        assert_eq!(forks.as_slice()[0], Fork::Boole);

        let forks = accept_forks(epoch, &schedule);
        assert_eq!(forks.len(), 1);
        assert_eq!(forks.as_slice()[0], Fork::Boole);

        let forks = process_forks(epoch, &schedule);
        assert_eq!(forks.len(), 1);
        assert_eq!(forks.as_slice()[0], Fork::Boole);
    }

    #[test]
    fn test_pre_subscribe_accept_vs_process() {
        let schedule = schedule_with_boole(FORK_EPOCH);
        let prep_start = FORK_EPOCH - FORK_PREPARATION_EPOCHS;

        // During pre-subscribe window: accept both but only process Alan
        for epoch_val in prep_start..FORK_EPOCH {
            let epoch = Epoch::new(epoch_val);

            let accept = accept_forks(epoch, &schedule);
            assert_eq!(
                accept.len(),
                2,
                "Should accept both forks at epoch {}",
                epoch_val
            );
            assert_eq!(accept.as_slice()[0], Fork::Alan);
            assert_eq!(accept.as_slice()[1], Fork::Boole);

            let process = process_forks(epoch, &schedule);
            assert_eq!(
                process.len(),
                1,
                "Should only process Alan at epoch {}",
                epoch_val
            );
            assert_eq!(process.as_slice()[0], Fork::Alan);
        }
    }

    #[test]
    fn test_immediate_cutoff_at_fork() {
        let schedule = schedule_with_boole(FORK_EPOCH);

        // Just before fork (F-1): still accept/subscribe Alan
        let sub = subscribe_forks(Epoch::new(99), &schedule);
        assert_eq!(sub.len(), 2, "Should dual-subscribe at F-1");

        // At fork (F): immediate cutoff to Boole only
        let sub = subscribe_forks(Epoch::new(FORK_EPOCH), &schedule);
        assert_eq!(sub.len(), 1, "Should only subscribe Boole at fork");
        assert_eq!(sub.as_slice()[0], Fork::Boole);

        let accept = accept_forks(Epoch::new(FORK_EPOCH), &schedule);
        assert_eq!(accept.len(), 1, "Should only accept Boole at fork");
        assert_eq!(accept.as_slice()[0], Fork::Boole);

        let process = process_forks(Epoch::new(FORK_EPOCH), &schedule);
        assert_eq!(process.len(), 1, "Should only process Boole at fork");
        assert_eq!(process.as_slice()[0], Fork::Boole);
    }

    #[test]
    fn test_fork_set_methods() {
        let alan = ForkSet::alan_only();
        assert_eq!(alan.len(), 1);
        assert!(!alan.is_empty());
        assert!(alan.contains(Fork::Alan));
        assert!(!alan.contains(Fork::Boole));

        let both = ForkSet::alan_and_boole();
        assert_eq!(both.len(), 2);
        assert!(both.contains(Fork::Alan));
        assert!(both.contains(Fork::Boole));

        let boole = ForkSet::boole_only();
        assert_eq!(boole.len(), 1);
        assert!(!boole.contains(Fork::Alan));
        assert!(boole.contains(Fork::Boole));
    }
}
