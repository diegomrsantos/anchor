use bls::PublicKeyBytes;
use rusqlite::{OptionalExtension, Transaction, params};
use ssv_types::{Cluster, ClusterId, Share, ValidatorMetadata};
use types::Address;

use super::{DatabaseError, NetworkDatabase, sql_operations};

/// Implements all cluster related functionality on the database
impl NetworkDatabase {
    pub(crate) fn insert_validator_tx(
        &self,
        cluster: &Cluster,
        validator: &ValidatorMetadata,
        shares: &[Share],
        tx: &Transaction<'_>,
    ) -> Result<(), DatabaseError> {
        // Insert the top level cluster data if it does not exist, and the associated validator
        // metadata
        tx.prepare_cached(sql_operations::INSERT_CLUSTER)?
            .execute(params![
                *cluster.cluster_id,       // cluster id
                cluster.owner.to_string(), // owner
            ])?;
        tx.prepare_cached(sql_operations::INSERT_VALIDATOR)?
            .execute(params![
                validator.public_key.to_string(), // validator public key
                *cluster.cluster_id,              // cluster id
                validator.index,                  // validator index
                validator.graffiti.0.as_slice(),  // graffiti
            ])?;

        // Insert a fee recipient address if one does not already exist
        tx.execute(
            "INSERT OR IGNORE INTO owners (owner, fee_recipient) VALUES (?, ?)",
            params![cluster.owner.to_string(), cluster.owner.to_string()],
        )?;

        for share in shares {
            tx.prepare_cached(sql_operations::INSERT_CLUSTER_MEMBER)?
                .execute(params![*share.cluster_id, share.operator_id])?;
            self.insert_share(tx, share, &validator.public_key)?;
        }

        Ok(())
    }

    pub fn commit_validator_added(
        &self,
        cluster: Cluster,
        validator: ValidatorMetadata,
        shares: Vec<Share>,
        cursor: crate::ProcessedEventCursor,
    ) -> Result<(), DatabaseError> {
        let owner = cluster.owner;
        self.commit_db_update(super::ProgressUpdate::Event(cursor), true, |tx| {
            self.bump_nonce_tx(&owner, tx)?;
            self.insert_validator_tx(&cluster, &validator, &shares, tx)
        })
    }

    pub fn commit_owner_nonce(
        &self,
        owner: Address,
        cursor: crate::ProcessedEventCursor,
    ) -> Result<(), DatabaseError> {
        self.commit_db_update(super::ProgressUpdate::Event(cursor), false, |tx| {
            self.bump_nonce_tx(&owner, tx)
        })
    }

    /// Inserts a new validator into the database. A new cluster will be created if this is the
    /// first validator for the cluster
    pub fn insert_validator(
        &self,
        cluster: Cluster,
        validator: &ValidatorMetadata,
        shares: Vec<Share>,
        tx: &Transaction<'_>,
    ) -> Result<(), DatabaseError> {
        self.insert_validator_tx(&cluster, validator, &shares, tx)?;

        Ok(())
    }

    pub(crate) fn update_status_tx(
        &self,
        cluster_id: ClusterId,
        status: bool,
        tx: &Transaction<'_>,
    ) -> Result<(), DatabaseError> {
        tx.prepare_cached(sql_operations::UPDATE_CLUSTER_STATUS)?
            .execute(params![
                status,      // status of the cluster (liquidated = false, active = true)
                *cluster_id  // Id of the cluster
            ])?;

        Ok(())
    }

    pub fn commit_cluster_status(
        &self,
        cluster_id: ClusterId,
        status: bool,
        cursor: crate::ProcessedEventCursor,
    ) -> Result<(), DatabaseError> {
        self.commit_db_update(super::ProgressUpdate::Event(cursor), true, |tx| {
            self.update_status_tx(cluster_id, status, tx)
        })
    }

    /// Mark the cluster as liquidated or active
    pub fn update_status(
        &self,
        cluster_id: ClusterId,
        status: bool,
        tx: &Transaction<'_>,
    ) -> Result<(), DatabaseError> {
        self.update_status_tx(cluster_id, status, tx)?;

        Ok(())
    }

    pub(crate) fn delete_validator_tx(
        &self,
        validator_pubkey: &PublicKeyBytes,
        tx: &Transaction<'_>,
    ) -> Result<(), DatabaseError> {
        tx.prepare_cached(sql_operations::DELETE_VALIDATOR)?
            .execute(params![validator_pubkey.to_string()])?;

        Ok(())
    }

    pub fn commit_validator_removed(
        &self,
        validator_pubkey: PublicKeyBytes,
        cursor: crate::ProcessedEventCursor,
    ) -> Result<(), DatabaseError> {
        self.commit_db_update(super::ProgressUpdate::Event(cursor), true, |tx| {
            self.delete_validator_tx(&validator_pubkey, tx)
        })
    }

    /// Delete a validator from a cluster. This will cascade and remove all corresponding share
    /// data for this validator. If this validator is the last one in the cluster, the cluster
    /// and all corresponding cluster members will also be removed
    pub fn delete_validator(
        &self,
        validator_pubkey: &PublicKeyBytes,
        tx: &Transaction<'_>,
    ) -> Result<(), DatabaseError> {
        self.delete_validator_tx(validator_pubkey, tx)?;

        Ok(())
    }

    pub(crate) fn bump_nonce_tx(
        &self,
        owner: &Address,
        tx: &Transaction<'_>,
    ) -> Result<(), DatabaseError> {
        tx.prepare_cached(sql_operations::BUMP_NONCE)?
            .execute(params![owner.to_string()])?;

        Ok(())
    }

    pub(crate) fn get_nonce(
        &self,
        owner: &Address,
        tx: &Transaction<'_>,
    ) -> Result<Option<u16>, DatabaseError> {
        tx.prepare_cached(sql_operations::GET_NONCE)?
            .query_row(params![owner.to_string()], |row| row.get(0))
            .optional()
            .map_err(DatabaseError::from)
    }

    /// Bump the nonce of the owner
    pub fn bump_and_get_nonce(
        &self,
        owner: &Address,
        tx: &Transaction<'_>,
    ) -> Result<u16, DatabaseError> {
        self.bump_nonce_tx(owner, tx)?;
        Ok(self.get_nonce(owner, tx)?.unwrap_or(0))
    }
}
