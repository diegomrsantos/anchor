use std::{collections::HashSet, path::Path, str::FromStr, sync::Arc, time::Duration};

use base64::prelude::*;
use bls::PublicKeyBytes;
use once_cell::sync::OnceCell;
use openssl::{pkey::Public, rsa::Rsa};
use r2d2::CustomizeConnection;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, params};
use ssv_types::{
    Cluster, ClusterId, CommitteeId, CommitteeInfo, IndexSet, Operator, OperatorId, Share,
    ValidatorIndex, ValidatorMetadata,
};
use tokio::sync::watch::{self, Receiver};
use types::Address;

pub use crate::{error::DatabaseError, slashing::SlashingProtection};

mod cluster_operations;
mod error;
mod keysplit_operations;
mod operator_operations;
mod schema;
mod share_operations;
pub mod slashing;
mod sql_operations;
mod validator_operations;

// Compile tests module for crate tests or when the feature is enabled, but keep it private.
#[cfg(any(test, feature = "test-utils"))]
mod tests;

// Public, narrow re-export of just the test utilities when the feature is enabled.
#[cfg(feature = "test-utils")]
#[doc(hidden)]
pub mod test_utils {
    pub use super::{slashing::NoOpSlashingProtection, tests::utils::*};
}

const WRITE_POOL_SIZE: u32 = 1;
const READ_POOL_SIZE: u32 = 8;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);

#[cfg(feature = "test-utils")]
static IN_MEMORY_DB_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

type Pool = r2d2::Pool<SqliteConnectionManager>;
type PoolConn = r2d2::PooledConnection<SqliteConnectionManager>;

#[derive(Debug)]
enum PubkeyOrId {
    Pubkey(Rsa<Public>),
    Id(OperatorId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessedEventCursor {
    pub block_number: u64,
    pub transaction_index: u64,
    pub log_index: u64,
}

/// Top level database handle. SQLite is the source of truth; callers should use the narrow read
/// APIs below instead of reconstructing a full in-memory network snapshot.
#[derive(Debug)]
pub struct NetworkDatabase {
    /// The public key or ID of our operator
    operator: PubkeyOrId,
    /// Lightweight revision notifications for consumers that need wakeups after observable writes.
    revision: watch::Sender<u64>,
    /// Connection pool used for writes and transactions.
    write_pool: Pool,
    /// Connection pool used for read-only lookups.
    read_pool: Pool,
}

#[derive(Clone, Copy)]
enum ProgressUpdate {
    None,
    Event(ProcessedEventCursor),
    Block(u64),
}

impl NetworkDatabase {
    /// Construct a new NetworkDatabase at the given path and the Public Key of the current operator
    pub fn new(
        path: &Path,
        pubkey: &Rsa<Public>,
        network_name: &str,
    ) -> Result<Self, DatabaseError> {
        let (write_pool, read_pool) = Self::open_or_create(path, network_name)?;
        let operator = PubkeyOrId::Pubkey(pubkey.clone());
        Ok(Self {
            operator,
            revision: watch::Sender::new(0),
            write_pool,
            read_pool,
        })
    }

    /// Construct a new NetworkDatabase using an in-memory database (test-only)
    /// This is more explicit than passing ":memory:" as a path
    #[cfg(feature = "test-utils")]
    pub fn new_in_memory(pubkey: &Rsa<Public>, network_name: &str) -> Result<Self, DatabaseError> {
        let (write_pool, read_pool) = Self::open_in_memory(network_name)?;
        let operator = PubkeyOrId::Pubkey(pubkey.clone());
        Ok(Self {
            operator,
            revision: watch::Sender::new(0),
            write_pool,
            read_pool,
        })
    }

    /// Act as if we had the pubkey of a certain operator
    pub fn new_as_impostor(
        path: &Path,
        operator: &OperatorId,
        network_name: &str,
    ) -> Result<Self, DatabaseError> {
        let (write_pool, read_pool) = Self::open_or_create(path, network_name)?;
        let operator = PubkeyOrId::Id(*operator);
        Ok(Self {
            operator,
            revision: watch::Sender::new(0),
            write_pool,
            read_pool,
        })
    }

    pub fn watch_revision(&self) -> Receiver<u64> {
        self.revision.subscribe()
    }

    pub fn get_own_id(&self) -> Result<Option<OperatorId>, DatabaseError> {
        match &self.operator {
            PubkeyOrId::Id(id) => Ok(Some(*id)),
            PubkeyOrId::Pubkey(pubkey) => {
                let encoded = BASE64_STANDARD.encode(
                    pubkey
                        .public_key_to_pem()
                        .expect("Failed to encode RsaPublicKey"),
                );
                let conn = self.read_connection()?;
                conn.prepare_cached(sql_operations::GET_OPERATOR_ID)?
                    .query_row(params![encoded], |row| row.get(0))
                    .optional()
                    .map_err(DatabaseError::from)
            }
        }
    }

    pub fn get_last_processed_block(&self) -> Result<u64, DatabaseError> {
        let conn = self.read_connection()?;
        conn.prepare_cached(sql_operations::GET_BLOCK_NUMBER)?
            .query_row(params![], |row| row.get(0))
            .map_err(DatabaseError::from)
    }

    pub fn get_last_processed_event(&self) -> Result<Option<ProcessedEventCursor>, DatabaseError> {
        let conn = self.read_connection()?;
        conn.prepare_cached(sql_operations::GET_PROCESSED_EVENT_CURSOR)?
            .query_row(params![], |row| {
                let block_number = row.get::<_, Option<u64>>(0)?;
                let transaction_index = row.get::<_, Option<u64>>(1)?;
                let log_index = row.get::<_, Option<u64>>(2)?;

                Ok(match (block_number, transaction_index, log_index) {
                    (Some(block_number), Some(transaction_index), Some(log_index)) => {
                        Some(ProcessedEventCursor {
                            block_number,
                            transaction_index,
                            log_index,
                        })
                    }
                    (None, None, None) => None,
                    _ => None,
                })
            })
            .map_err(DatabaseError::from)
    }

    pub fn next_block_to_fetch(&self, deployment_block: u64) -> Result<u64, DatabaseError> {
        Ok(self
            .get_last_processed_event()?
            .map(|cursor| cursor.block_number)
            .unwrap_or(self.get_last_processed_block()?.saturating_add(1))
            .max(deployment_block))
    }

    pub fn get_max_operator_id_seen(&self) -> Result<Option<u64>, DatabaseError> {
        let conn = self.read_connection()?;
        conn.prepare_cached(sql_operations::GET_MAX_OPERATOR_ID_SEEN)?
            .query_row(params![], |row| row.get(0))
            .map_err(DatabaseError::from)
    }

    pub fn operator_exists(&self, id: &OperatorId) -> Result<bool, DatabaseError> {
        let conn = self.read_connection()?;
        let exists = conn
            .prepare_cached(sql_operations::GET_OPERATOR_STATUS)?
            .query_row(params![id], |_row| Ok(()))
            .optional()?
            .is_some();
        Ok(exists)
    }

    pub fn get_operator(&self, id: &OperatorId) -> Result<Option<Operator>, DatabaseError> {
        let conn = self.read_connection()?;
        conn.prepare_cached(sql_operations::GET_OPERATOR_BY_ID)?
            .query_row(params![id], |row| row.try_into())
            .optional()
            .map_err(DatabaseError::from)
    }

    pub fn get_all_operators(&self) -> Result<Vec<Operator>, DatabaseError> {
        let conn = self.read_connection()?;
        let mut stmt = conn.prepare_cached(sql_operations::GET_ALL_OPERATORS)?;
        stmt.query_map([], |row| row.try_into())?
            .map(|result| result.map_err(DatabaseError::from))
            .collect()
    }

    pub fn get_next_nonce(&self, owner: &Address) -> Result<u16, DatabaseError> {
        let conn = self.read_connection()?;
        let nonce: Option<Option<u16>> = conn
            .prepare_cached(sql_operations::GET_NONCE)?
            .query_row(params![owner.to_string()], |row| row.get(0))
            .optional()?;
        Ok(nonce.flatten().map_or(0, |value| value.saturating_add(1)))
    }

    pub fn read_fee_recipient_for_owner(
        &self,
        owner: &Address,
    ) -> Result<Option<Address>, DatabaseError> {
        let conn = self.read_connection()?;
        let mut stmt = conn.prepare_cached(sql_operations::GET_OWNER_FEE_RECIPIENT)?;

        let result = stmt.query_row(params![owner.to_string()], |row| {
            let address_str: Option<String> = row.get(0)?;
            if let Some(address_str) = address_str {
                let address = address_str.parse().map_err(|e| {
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

    pub fn has_validator_metadata(
        &self,
        validator_pubkey: &PublicKeyBytes,
    ) -> Result<bool, DatabaseError> {
        let conn = self.read_connection()?;
        let exists = conn
            .prepare_cached(sql_operations::GET_VALIDATOR_BY_PUBKEY)?
            .query_row(params![validator_pubkey.to_string()], |_row| Ok(()))
            .optional()?
            .is_some();
        Ok(exists)
    }

    pub fn get_validator_metadata(
        &self,
        validator_pubkey: &PublicKeyBytes,
    ) -> Result<Option<ValidatorMetadata>, DatabaseError> {
        let conn = self.read_connection()?;
        conn.prepare_cached(sql_operations::GET_VALIDATOR_BY_PUBKEY)?
            .query_row(params![validator_pubkey.to_string()], |row| row.try_into())
            .optional()
            .map_err(DatabaseError::from)
    }

    pub fn get_cluster_by_validator_pubkey(
        &self,
        validator_pubkey: &PublicKeyBytes,
    ) -> Result<Option<Cluster>, DatabaseError> {
        let conn = self.read_connection()?;
        let cluster_id = conn
            .prepare_cached(sql_operations::GET_CLUSTER_BY_VALIDATOR_PUBKEY)?
            .query_row(params![validator_pubkey.to_string()], |row| {
                Ok(ClusterId(row.get::<_, [u8; 32]>("cluster_id")?))
            })
            .optional()?;
        self.cluster_by_id(&conn, cluster_id)
    }

    pub fn get_cluster(&self, cluster_id: ClusterId) -> Result<Option<Cluster>, DatabaseError> {
        let conn = self.read_connection()?;
        self.cluster_by_id(&conn, Some(cluster_id))
    }

    pub fn share_exists_for_validator(
        &self,
        validator_pubkey: &PublicKeyBytes,
    ) -> Result<bool, DatabaseError> {
        let Some(own_id) = self.get_own_id()? else {
            return Ok(false);
        };
        let conn = self.read_connection()?;
        let exists = conn
            .prepare_cached(sql_operations::SHARE_EXISTS_FOR_OPERATOR_AND_VALIDATOR)?
            .query_row(params![validator_pubkey.to_string(), own_id], |_row| Ok(()))
            .optional()?
            .is_some();
        Ok(exists)
    }

    pub fn get_own_share(
        &self,
        validator_pubkey: &PublicKeyBytes,
    ) -> Result<Option<Share>, DatabaseError> {
        let Some(own_id) = self.get_own_id()? else {
            return Ok(None);
        };
        let conn = self.read_connection()?;
        conn.prepare_cached(sql_operations::GET_OWN_SHARE_BY_VALIDATOR)?
            .query_row(params![validator_pubkey.to_string(), own_id], |row| {
                row.try_into()
            })
            .optional()
            .map_err(DatabaseError::from)
    }

    pub fn validator_indices(&self) -> Result<Vec<u64>, DatabaseError> {
        let conn = self.read_connection()?;
        let mut stmt = conn.prepare_cached(sql_operations::GET_VALIDATOR_INDICES)?;
        stmt.query_map([], |row| row.get::<_, ValidatorIndex>(0))?
            .map(|result| result.map(u64::from).map_err(DatabaseError::from))
            .collect()
    }

    pub fn get_committee_info_by_committee_id(
        &self,
        committee_id: &CommitteeId,
    ) -> Result<Option<CommitteeInfo>, DatabaseError> {
        let conn = self.read_connection()?;
        let Some((cluster_id, committee_members)) =
            self.find_committee_members(&conn, committee_id)?
        else {
            return Ok(None);
        };

        Ok(Some(CommitteeInfo {
            committee_members,
            validator_indices: self.validator_indices_for_cluster(&conn, cluster_id)?,
        }))
    }

    pub fn get_committee_info_by_validator_pk(
        &self,
        validator_pubkey: &PublicKeyBytes,
    ) -> Result<Option<CommitteeInfo>, DatabaseError> {
        let Some(metadata) = self.get_validator_metadata(validator_pubkey)? else {
            return Ok(None);
        };
        let conn = self.read_connection()?;
        let committee_members = self.cluster_members_for_cluster(&conn, metadata.cluster_id)?;

        Ok(Some(CommitteeInfo {
            committee_members,
            validator_indices: metadata.index.map(|idx| vec![idx]).unwrap_or_default(),
        }))
    }

    pub fn own_cluster_count(&self) -> Result<usize, DatabaseError> {
        let Some(own_id) = self.get_own_id()? else {
            return Ok(0);
        };
        let conn = self.read_connection()?;
        let mut stmt = conn.prepare_cached(sql_operations::GET_OWN_CLUSTER_IDS)?;
        let cluster_ids = stmt
            .query_map(params![own_id], |row| row.get::<_, [u8; 32]>(0))?
            .map(|result| result.map_err(DatabaseError::from))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(cluster_ids.len())
    }

    pub fn own_committee_operator_sets(&self) -> Result<Vec<Vec<OperatorId>>, DatabaseError> {
        let Some(own_id) = self.get_own_id()? else {
            return Ok(Vec::new());
        };
        let conn = self.read_connection()?;
        let mut stmt = conn.prepare_cached(sql_operations::GET_OWN_CLUSTER_IDS)?;
        let cluster_ids = stmt
            .query_map(params![own_id], |row| Ok(ClusterId(row.get(0)?)))?
            .map(|result| result.map_err(DatabaseError::from))
            .collect::<Result<Vec<_>, _>>()?;

        cluster_ids
            .into_iter()
            .map(|cluster_id| {
                self.cluster_members_for_cluster(&conn, cluster_id)
                    .map(|members| members.into_iter().collect::<Vec<_>>())
            })
            .collect()
    }

    pub fn is_member_of_committee(
        &self,
        committee_id: &CommitteeId,
        own_id: OperatorId,
    ) -> Result<bool, DatabaseError> {
        let conn = self.read_connection()?;
        Ok(self
            .find_committee_members(&conn, committee_id)?
            .map(|(_, members): (ClusterId, IndexSet<OperatorId>)| members.contains(&own_id))
            .unwrap_or(false))
    }

    pub fn list_validators(&self) -> Result<Vec<ValidatorMetadata>, DatabaseError> {
        let conn = self.read_connection()?;
        let mut stmt = conn.prepare_cached(sql_operations::GET_ALL_VALIDATORS)?;
        stmt.query_map([], |row| row.try_into())?
            .map(|result| result.map_err(DatabaseError::from))
            .collect()
    }

    pub fn list_committees(&self) -> Result<Vec<(CommitteeId, CommitteeInfo)>, DatabaseError> {
        let conn = self.read_connection()?;
        let mut stmt = conn.prepare_cached(sql_operations::GET_ALL_CLUSTERS)?;
        let clusters = stmt
            .query_map([], |row| {
                let cluster_id = ClusterId(row.get::<_, [u8; 32]>("cluster_id")?);
                let owner = Address::from_str(&row.get::<_, String>("owner")?).map_err(|err| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Text,
                        Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, err)),
                    )
                })?;
                let fee_recipient = row
                    .get::<_, Option<String>>("fee_recipient")?
                    .map(|value| {
                        Address::from_str(&value).map_err(|err| {
                            rusqlite::Error::FromSqlConversionFailure(
                                2,
                                rusqlite::types::Type::Text,
                                Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, err)),
                            )
                        })
                    })
                    .transpose()?
                    .unwrap_or(owner);
                let liquidated = row.get::<_, bool>("liquidated")?;
                Ok((cluster_id, owner, fee_recipient, liquidated))
            })?
            .map(|result| result.map_err(DatabaseError::from))
            .collect::<Result<Vec<_>, _>>()?;

        clusters
            .into_iter()
            .map(|(cluster_id, _owner, _fee_recipient, _liquidated)| {
                let committee_members = self.cluster_members_for_cluster(&conn, cluster_id)?;
                let validator_indices = self.validator_indices_for_cluster(&conn, cluster_id)?;
                let committee_id = committee_members.iter().copied().collect::<Vec<_>>().into();
                Ok((
                    committee_id,
                    CommitteeInfo {
                        committee_members,
                        validator_indices,
                    },
                ))
            })
            .collect()
    }

    pub fn get_validator_index(
        &self,
        validator_pubkey: &PublicKeyBytes,
    ) -> Result<Option<ValidatorIndex>, DatabaseError> {
        let conn = self.read_connection()?;
        conn.prepare_cached(sql_operations::GET_VALIDATOR_INDEX)?
            .query_row(params![validator_pubkey.to_string()], |row| row.get(0))
            .optional()
            .map_err(DatabaseError::from)
    }

    pub fn validator_pubkeys_for_committee(
        &self,
        committee_id: &CommitteeId,
    ) -> Result<HashSet<PublicKeyBytes>, DatabaseError> {
        let conn = self.read_connection()?;
        let Some((cluster_id, _)) = self.find_committee_members(&conn, committee_id)? else {
            return Ok(HashSet::new());
        };
        let mut stmt = conn.prepare_cached(sql_operations::GET_VALIDATOR_PUBKEYS_BY_CLUSTER)?;
        stmt.query_map(params![cluster_id.0], |row| {
            let pubkey = row.get::<_, String>(0)?;
            PublicKeyBytes::from_str(&pubkey).map_err(|err| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, err)),
                )
            })
        })?
        .map(|result| result.map_err(DatabaseError::from))
        .collect()
    }

    pub fn active_voting_pubkeys(&self) -> Result<Vec<PublicKeyBytes>, DatabaseError> {
        let Some(own_id) = self.get_own_id()? else {
            return Ok(Vec::new());
        };
        let conn = self.read_connection()?;
        let mut stmt = conn.prepare_cached(sql_operations::GET_ACTIVE_VOTING_PUBKEYS)?;
        stmt.query_map(params![own_id], |row| {
            let pubkey = row.get::<_, String>(0)?;
            PublicKeyBytes::from_str(&pubkey).map_err(|err| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, err)),
                )
            })
        })?
        .map(|result| result.map_err(DatabaseError::from))
        .collect()
    }

    pub fn own_share_count(&self) -> Result<usize, DatabaseError> {
        let Some(own_id) = self.get_own_id()? else {
            return Ok(0);
        };
        let conn = self.read_connection()?;
        conn.prepare_cached(sql_operations::COUNT_OWN_SHARES)?
            .query_row(params![own_id], |row| row.get(0))
            .map_err(DatabaseError::from)
    }

    pub fn validators_needing_index(&self) -> Result<Vec<PublicKeyBytes>, DatabaseError> {
        let conn = self.read_connection()?;
        let mut stmt = conn.prepare_cached(sql_operations::GET_VALIDATORS_NEEDING_INDEX)?;
        stmt.query_map([], |row| {
            let pubkey = row.get::<_, String>(0)?;
            PublicKeyBytes::from_str(&pubkey).map_err(|err| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, err)),
                )
            })
        })?
        .map(|result| result.map_err(DatabaseError::from))
        .collect()
    }

    pub fn mark_event_processed(&self, cursor: ProcessedEventCursor) -> Result<(), DatabaseError> {
        self.commit_db_update(ProgressUpdate::Event(cursor), false, |_| Ok(()))
    }

    pub fn advance_processed_block(&self, block_number: u64) -> Result<(), DatabaseError> {
        self.commit_db_update(ProgressUpdate::Block(block_number), false, |_| Ok(()))
    }

    /// Update the last processed block number in the database
    /// Also, trigger a notification for other code to act on the new state
    pub fn processed_block(
        &self,
        block_number: u64,
        tx: &Transaction<'_>,
    ) -> Result<(), DatabaseError> {
        tx.prepare_cached(sql_operations::UPDATE_BLOCK_NUMBER)?
            .execute(params![block_number])?;
        self.bump_revision();
        Ok(())
    }

    /// Update the largest seen OperatorId in the database
    pub fn set_max_operator_id_seen(
        &self,
        operator_id: u64,
        tx: &Transaction<'_>,
    ) -> Result<(), DatabaseError> {
        tx.prepare_cached(sql_operations::SET_MAX_OPERATOR_ID_SEEN)?
            .execute(params![operator_id])?;

        Ok(())
    }

    // Open an existing database at the given `path`, or create one if none exists.
    fn open_or_create(path: &Path, network_name: &str) -> Result<(Pool, Pool), DatabaseError> {
        schema::ensure_up_to_date(path, network_name)?;
        Self::open_conn_pools(path)
    }

    // Build connection pools for file-based databases.
    fn open_conn_pools(path: &Path) -> Result<(Pool, Pool), DatabaseError> {
        let write_manager = SqliteConnectionManager::file(path);
        let write_pool = Pool::builder()
            .max_size(WRITE_POOL_SIZE)
            .connection_timeout(CONNECTION_TIMEOUT)
            .connection_customizer(Box::new(AnchorWriteConnection))
            .build(write_manager)?;

        let read_manager = SqliteConnectionManager::file(path)
            .with_flags(OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI);
        let read_pool = Pool::builder()
            .max_size(READ_POOL_SIZE)
            .connection_timeout(CONNECTION_TIMEOUT)
            .connection_customizer(Box::new(AnchorReadConnection))
            .build(read_manager)?;

        Ok((write_pool, read_pool))
    }

    // Build a new connection pool for in-memory databases (test-only)
    // In-memory databases bypass schema migrations and are initialized via connection customizer
    #[cfg(feature = "test-utils")]
    fn open_in_memory(network_name: &str) -> Result<(Pool, Pool), DatabaseError> {
        let db_id = IN_MEMORY_DB_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let uri = format!("file:anchor_test_{db_id}?mode=memory&cache=shared");

        let write_manager = SqliteConnectionManager::file(&uri).with_flags(
            OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_URI,
        );
        let write_pool = Pool::builder()
            .max_size(WRITE_POOL_SIZE)
            .connection_timeout(CONNECTION_TIMEOUT)
            .connection_customizer(Box::new(InMemoryCustomizeConnection {
                network_name: network_name.to_string(),
            }))
            .build(write_manager)?;

        let read_manager = SqliteConnectionManager::file(&uri).with_flags(
            OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_URI,
        );
        let read_pool = Pool::builder()
            .max_size(READ_POOL_SIZE)
            .connection_timeout(CONNECTION_TIMEOUT)
            .connection_customizer(Box::new(InMemoryCustomizeConnection {
                network_name: network_name.to_string(),
            }))
            .build(read_manager)?;

        Ok((write_pool, read_pool))
    }

    // Open a new write connection
    pub fn connection(&self) -> Result<PoolConn, DatabaseError> {
        Ok(self.write_pool.get()?)
    }

    pub fn read_connection(&self) -> Result<PoolConn, DatabaseError> {
        Ok(self.read_pool.get()?)
    }

    fn cluster_members_for_cluster(
        &self,
        conn: &PoolConn,
        cluster_id: ClusterId,
    ) -> Result<IndexSet<OperatorId>, DatabaseError> {
        let mut stmt = conn.prepare_cached(sql_operations::GET_CLUSTER_MEMBERS)?;
        let mut members = stmt
            .query_map(params![cluster_id.0], |row| row.get::<_, OperatorId>(0))?
            .map(|result| result.map_err(DatabaseError::from))
            .collect::<Result<Vec<_>, _>>()?;
        members.sort();
        Ok(members.into_iter().collect())
    }

    fn cluster_by_id(
        &self,
        conn: &PoolConn,
        cluster_id: Option<ClusterId>,
    ) -> Result<Option<Cluster>, DatabaseError> {
        let Some(cluster_id) = cluster_id else {
            return Ok(None);
        };
        let cluster_members = self.cluster_members_for_cluster(conn, cluster_id)?;
        let cluster_members = cluster_members
            .iter()
            .copied()
            .map(|operator_id| ssv_types::ClusterMember {
                operator_id,
                cluster_id,
            })
            .collect::<Vec<_>>();

        let cluster = conn
            .prepare_cached(sql_operations::GET_CLUSTER_BY_ID)?
            .query_row(params![cluster_id.0], |row| {
                Cluster::try_from((row, cluster_members.clone()))
            })
            .optional()?;
        Ok(cluster)
    }

    fn validator_indices_for_cluster(
        &self,
        conn: &PoolConn,
        cluster_id: ClusterId,
    ) -> Result<Vec<ValidatorIndex>, DatabaseError> {
        let mut stmt = conn.prepare_cached(sql_operations::GET_CLUSTER_VALIDATOR_INDICES)?;
        stmt.query_map(params![cluster_id.0], |row| row.get::<_, ValidatorIndex>(0))?
            .map(|result| result.map_err(DatabaseError::from))
            .collect()
    }

    fn find_committee_members(
        &self,
        conn: &PoolConn,
        committee_id: &CommitteeId,
    ) -> Result<Option<(ClusterId, IndexSet<OperatorId>)>, DatabaseError> {
        let mut stmt = conn.prepare_cached(sql_operations::GET_ALL_CLUSTER_MEMBERS)?;
        let rows = stmt.query_map([], |row| {
            Ok((
                ClusterId(row.get::<_, [u8; 32]>(0)?),
                row.get::<_, OperatorId>(1)?,
            ))
        })?;

        let mut current_cluster_id = None;
        let mut current_members = Vec::new();

        for row in rows {
            let (cluster_id, operator_id) = row?;
            match current_cluster_id {
                Some(existing) if existing == cluster_id => current_members.push(operator_id),
                Some(existing) => {
                    if let Some(found) =
                        Self::match_committee(existing, &mut current_members, committee_id)
                    {
                        return Ok(Some(found));
                    }
                    current_cluster_id = Some(cluster_id);
                    current_members.push(operator_id);
                }
                None => {
                    current_cluster_id = Some(cluster_id);
                    current_members.push(operator_id);
                }
            }
        }

        Ok(current_cluster_id.and_then(|cluster_id| {
            Self::match_committee(cluster_id, &mut current_members, committee_id)
        }))
    }

    fn match_committee(
        cluster_id: ClusterId,
        members: &mut Vec<OperatorId>,
        committee_id: &CommitteeId,
    ) -> Option<(ClusterId, IndexSet<OperatorId>)> {
        members.sort();
        let operator_ids = members.clone();
        let index_set = members.drain(..).collect::<IndexSet<_>>();
        (CommitteeId::from(operator_ids) == *committee_id).then_some((cluster_id, index_set))
    }

    /// Atomically commit a database write and then notify interested services via revision bump.
    ///
    /// If `notify` is `true`, wake subscribers that should react to observable state changes.
    /// Use `false` for internal bookkeeping (nonce bumps, cursor-only advances) that does not
    /// change observable validator/operator state.
    fn commit_db_update(
        &self,
        progress: ProgressUpdate,
        notify: bool,
        apply_tx: impl FnOnce(&Transaction<'_>) -> Result<(), DatabaseError>,
    ) -> Result<(), DatabaseError> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;

        apply_tx(&tx)?;
        self.apply_progress_to_tx(progress, &tx)?;
        tx.commit()?;

        if notify {
            self.bump_revision();
        }

        Ok(())
    }

    fn apply_progress_to_tx(
        &self,
        progress: ProgressUpdate,
        tx: &Transaction<'_>,
    ) -> Result<(), DatabaseError> {
        match progress {
            ProgressUpdate::None => Ok(()),
            ProgressUpdate::Event(cursor) => tx
                .prepare_cached(sql_operations::SET_PROCESSED_EVENT_CURSOR)?
                .execute(params![
                    cursor.block_number,
                    cursor.transaction_index,
                    cursor.log_index
                ])
                .map(|_| ())
                .map_err(DatabaseError::from),
            ProgressUpdate::Block(block_number) => tx
                .prepare_cached(sql_operations::UPDATE_BLOCK_NUMBER)?
                .execute(params![block_number])
                .map(|_| ())
                .map_err(DatabaseError::from),
        }
    }

    fn bump_revision(&self) {
        self.revision
            .send_modify(|revision| *revision = revision.saturating_add(1));
    }
}

#[derive(Debug)]
struct AnchorWriteConnection;

impl CustomizeConnection<Connection, rusqlite::Error> for AnchorWriteConnection {
    fn on_acquire(&self, conn: &mut Connection) -> rusqlite::Result<()> {
        conn.pragma_update(None, "journal_mode", "wal")
    }
}

#[derive(Debug)]
struct AnchorReadConnection;

impl CustomizeConnection<Connection, rusqlite::Error> for AnchorReadConnection {
    fn on_acquire(&self, conn: &mut Connection) -> rusqlite::Result<()> {
        conn.pragma_update(None, "query_only", "on")
    }
}

#[cfg(feature = "test-utils")]
#[derive(Debug)]
struct InMemoryCustomizeConnection {
    network_name: String,
}

#[cfg(feature = "test-utils")]
impl CustomizeConnection<Connection, rusqlite::Error> for InMemoryCustomizeConnection {
    fn on_acquire(&self, conn: &mut Connection) -> rusqlite::Result<()> {
        // For in-memory databases, create schema on each connection
        let _ = schema::create_initial_schema(conn, &self.network_name);
        conn.pragma_update(None, "read_uncommitted", "on")?;
        Ok(())
    }
}

/// A helper to get the operator ID of the current operator. Caches the ID after successfully
/// retrieving it to avoid locking the state further.
#[derive(Clone)]
pub enum OwnOperatorId {
    /// The operator ID was known when the `OwnOperatorId` was created.
    Known(OperatorId),
    /// The operator ID was not known when the `OwnOperatorId` was created. It will be retrieved
    /// from the `receiver` and cached in the `id` on first success.
    FromDatabase {
        database: Arc<NetworkDatabase>,
        /// We use a `OnceLock` so that `get` can be called without a mutable reference.
        id: OnceCell<OperatorId>,
    },
}

impl OwnOperatorId {
    /// Creates the `OwnOperatorId` to either immediately store the operator ID or to recheck it on
    /// later `get` calls.
    pub fn new(database: Arc<NetworkDatabase>) -> Self {
        if let Ok(Some(operator_id)) = database.get_own_id() {
            Self::Known(operator_id)
        } else {
            Self::FromDatabase {
                database,
                id: OnceCell::new(),
            }
        }
    }

    /// Get the operator ID if it is available. Caches the ID internally after the first successful
    /// call to avoid locking the state in the future. This is possible because the own Operator ID
    /// never changes.
    pub fn get(&self) -> Option<OperatorId> {
        match self {
            Self::Known(id) => Some(*id),
            Self::FromDatabase { database, id } => {
                // Switch to `std`'s OnceLock as soon as `get_or_try_init` is stable
                id.get_or_try_init(|| database.get_own_id().ok().flatten().ok_or(()))
                    .ok()
                    .copied()
            }
        }
    }
}

impl From<OperatorId> for OwnOperatorId {
    fn from(operator_id: OperatorId) -> Self {
        Self::Known(operator_id)
    }
}
