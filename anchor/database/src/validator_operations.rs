use std::{collections::HashMap, str::FromStr};

use bls::PublicKeyBytes;
use rusqlite::{Transaction, params};
use ssv_types::ValidatorIndex;
use types::{Address, Graffiti};

use crate::{DatabaseError, NetworkDatabase, sql_operations};

/// Implements all validator specific database functionality
impl NetworkDatabase {
    pub(crate) fn update_fee_recipient_tx(
        &self,
        owner: Address,
        fee_recipient: Address,
        tx: &Transaction<'_>,
    ) -> Result<(), DatabaseError> {
        tx.prepare_cached(sql_operations::INSERT_OR_UPDATE_OWNER_FEE_RECIPIENT)?
            .execute(params![
                owner.to_string(),         // Owner of the cluster
                fee_recipient.to_string()  // New fee recipient address for entire cluster
            ])?;

        Ok(())
    }

    pub fn commit_fee_recipient_updated(
        &self,
        owner: Address,
        fee_recipient: Address,
        cursor: crate::ProcessedEventCursor,
    ) -> Result<(), DatabaseError> {
        self.commit_db_update(super::ProgressUpdate::Event(cursor), true, |tx| {
            self.update_fee_recipient_tx(owner, fee_recipient, tx)
        })
    }

    /// Update the fee recipient address for all validators in a cluster
    pub fn update_fee_recipient(
        &self,
        owner: Address,
        fee_recipient: Address,
        tx: &Transaction<'_>,
    ) -> Result<(), DatabaseError> {
        self.update_fee_recipient_tx(owner, fee_recipient, tx)?;
        Ok(())
    }

    /// Get the fee recipient for an owner
    /// Returns Some(address) if found, None otherwise
    pub fn fee_recipient_for_owner(
        &self,
        owner: &Address,
        tx: &Transaction<'_>,
    ) -> Result<Option<Address>, DatabaseError> {
        let mut stmt = tx.prepare_cached(sql_operations::GET_OWNER_FEE_RECIPIENT)?;

        let result = stmt.query_row(params![owner.to_string()], |row| {
            let address_str: Option<String> = row.get(0)?;
            // If the address is None, return None
            if let Some(address_str) = address_str {
                let address = Address::from_str(&address_str).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?;
                Ok(Some(address))
            } else {
                Ok(None)
            }
        });

        match result {
            Ok(address) => Ok(address),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(DatabaseError::from(e)),
        }
    }

    /// Update the Graffiti for a Validator
    pub fn update_graffiti(
        &self,
        validator_pubkey: &PublicKeyBytes,
        graffiti: Graffiti,
        tx: &Transaction<'_>,
    ) -> Result<(), DatabaseError> {
        // Update the database
        tx.prepare_cached(sql_operations::SET_GRAFFITI)?
            .execute(params![
                graffiti.0.as_slice(),        // New graffiti
                validator_pubkey.to_string()  // The public key of the validator
            ])?;
        Ok(())
    }

    pub fn set_validator_indices(
        &self,
        map: HashMap<PublicKeyBytes, ValidatorIndex>,
    ) -> Result<(), DatabaseError> {
        let tx_map = map.clone();
        self.commit_db_update(super::ProgressUpdate::None, true, |tx| {
            self.set_validator_indices_tx(&tx_map, tx)
        })
    }

    pub(crate) fn set_validator_indices_tx(
        &self,
        map: &HashMap<PublicKeyBytes, ValidatorIndex>,
        tx: &Transaction<'_>,
    ) -> Result<(), DatabaseError> {
        for (public_key, index) in map {
            tx.prepare_cached(sql_operations::SET_INDEX)?
                .execute(params![
                    index,                  // New index
                    public_key.to_string()  // The public key of the validator
                ])?;
        }

        Ok(())
    }
}
