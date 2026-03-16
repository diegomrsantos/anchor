use slot_clock::SlotClock;
use ssv_types::OperatorId;
use tracing::{debug, error, warn};
use types::EthSpec;

use crate::{
    SubnetId, TopicEvent, message_rate, service::SubnetService, subscriptions::ServiceState,
    topic::create_topic,
};

impl<S: SlotClock> SubnetService<S> {
    /// Emit updated message-rate estimates for gossipsub topic scoring.
    ///
    /// Gossipsub uses these rates to set per-topic scoring parameters that detect:
    /// - Flooding (too many messages vs expected)
    /// - Underperformance (too few messages vs expected)
    ///
    /// Rates are recalculated at each epoch because committee compositions and
    /// sync committee memberships can change.
    pub(crate) async fn send_scoring_rate_updates<E: EthSpec>(&self, service_state: &ServiceState) {
        let Some(fork) = service_state.forks.get(&service_state.fork_to_score) else {
            error!(fork = ?service_state.fork_to_score, "Failed to get fork to score");
            return;
        };

        debug!(
            subnet_count = fork.currently_subscribed.len(),
            "Sending updated scoring rates for all topics"
        );

        let topic_prefix = service_state
            .fork_to_score
            .topic_prefix(self.router().fork_schedule().network_name());
        for subnet in &fork.currently_subscribed {
            let topic = create_topic(&topic_prefix, *subnet);

            let committees_info = self.get_committee_info_for_subnet(subnet, &fork.config);

            let rate = message_rate::calculate_message_rate_for_topic::<E>(
                &committees_info,
                &self.chain_spec,
            );

            if self
                .tx
                .send(TopicEvent::RateUpdate {
                    topic,
                    message_rate: rate,
                })
                .await
                .is_err()
            {
                warn!("Network no longer listening for topic events");
                return;
            }
        }
    }

    /// Compute a subnet's message rate if scoring is enabled.
    pub(crate) fn subnet_message_rate<E: EthSpec>(
        &self,
        subnet: &SubnetId,
        fork_config: &fork::ForkConfig,
    ) -> Option<f64> {
        if self.disable_gossipsub_topic_scoring {
            return None;
        }

        let committees_info = self.get_committee_info_for_subnet(subnet, fork_config);
        Some(message_rate::calculate_message_rate_for_topic::<E>(
            &committees_info,
            &self.chain_spec,
        ))
    }

    /// Get committee info for all clusters on a specific subnet.
    ///
    /// This function retrieves clusters that map to the given subnet and converts
    /// them to `CommitteeInfo` which includes both committee members and validator indices.
    fn get_committee_info_for_subnet(
        &self,
        subnet: &SubnetId,
        fork_config: &fork::ForkConfig,
    ) -> Vec<ssv_types::CommitteeInfo> {
        self.db
            .list_committees()
            .map_err(|err| {
                error!(?err, "Failed to load committees for subnet scoring");
            })
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(_, committee)| {
                let operator_ids: Vec<OperatorId> =
                    committee.committee_members.iter().copied().collect();
                match SubnetId::from_operators_for_fork(&operator_ids, fork_config.fork) {
                    Ok(cluster_subnet) if cluster_subnet == *subnet => Some(committee),
                    Ok(_) | Err(_) => None,
                }
            })
            .collect()
    }
}
