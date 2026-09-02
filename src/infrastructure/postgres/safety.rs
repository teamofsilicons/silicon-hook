//! Per-hook client-address abuse state.

use std::net::IpAddr;

use time::OffsetDateTime;

use crate::domain::{
    HookId,
    safety::{BlockCheck, IpBlockState, StrikeOutcome},
};

use super::{PostgresStore, StoreError, models::IpBlockRow};

impl PostgresStore {
    /// Evaluates whether an address may send to a hook and counts a rejection
    /// when it may not.
    ///
    /// # Errors
    ///
    /// Returns a PostgreSQL failure or corrupt counters.
    pub async fn check_ip_block(
        &self,
        hook_id: HookId,
        remote_ip: IpAddr,
        now: OffsetDateTime,
    ) -> Result<BlockCheck, StoreError> {
        let row = sqlx::query_as::<_, IpBlockRow>(
            "SELECT strikes, blocks, blocked_until, permanent
             FROM hook_private.ip_blocks
             WHERE hook_id = $1 AND remote_ip = $2",
        )
        .bind(hook_id.as_uuid())
        .bind(remote_ip)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(BlockCheck::Allowed);
        };
        let check = IpBlockState::try_from(row)?.check(now);
        if check != BlockCheck::Allowed {
            sqlx::query(
                "UPDATE hook_private.ip_blocks
                 SET rejected_requests = rejected_requests + 1, updated_at = $3
                 WHERE hook_id = $1 AND remote_ip = $2",
            )
            .bind(hook_id.as_uuid())
            .bind(remote_ip)
            .bind(now)
            .execute(&self.pool)
            .await?;
        }
        Ok(check)
    }

    /// Records an unverified request and applies the block policy.
    ///
    /// # Errors
    ///
    /// Returns a PostgreSQL failure or corrupt counters.
    pub async fn record_unverified_request(
        &self,
        hook_id: HookId,
        remote_ip: IpAddr,
        now: OffsetDateTime,
    ) -> Result<StrikeOutcome, StoreError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO hook_private.ip_blocks (
                 hook_id, remote_ip, first_seen_at, updated_at
             ) VALUES ($1, $2, $3, $3)
             ON CONFLICT (hook_id, remote_ip) DO NOTHING",
        )
        .bind(hook_id.as_uuid())
        .bind(remote_ip)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        let row = sqlx::query_as::<_, IpBlockRow>(
            "SELECT strikes, blocks, blocked_until, permanent
             FROM hook_private.ip_blocks
             WHERE hook_id = $1 AND remote_ip = $2
             FOR UPDATE",
        )
        .bind(hook_id.as_uuid())
        .bind(remote_ip)
        .fetch_one(&mut *transaction)
        .await?;
        let mut state = IpBlockState::try_from(row)?;
        let outcome = state.record_unverified(now);
        sqlx::query(
            "UPDATE hook_private.ip_blocks
             SET strikes = $3, blocks = $4, blocked_until = $5, permanent = $6, updated_at = $7
             WHERE hook_id = $1 AND remote_ip = $2",
        )
        .bind(hook_id.as_uuid())
        .bind(remote_ip)
        .bind(i32::try_from(state.strikes).unwrap_or(i32::MAX))
        .bind(i32::try_from(state.blocks).unwrap_or(i32::MAX))
        .bind(state.blocked_until)
        .bind(state.permanent)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(outcome)
    }
}

impl TryFrom<IpBlockRow> for IpBlockState {
    type Error = StoreError;

    fn try_from(row: IpBlockRow) -> Result<Self, Self::Error> {
        Ok(Self {
            strikes: u32::try_from(row.strikes)
                .map_err(|error| StoreError::corrupt("ip block", error))?,
            blocks: u32::try_from(row.blocks)
                .map_err(|error| StoreError::corrupt("ip block", error))?,
            blocked_until: row.blocked_until,
            permanent: row.permanent,
        })
    }
}
