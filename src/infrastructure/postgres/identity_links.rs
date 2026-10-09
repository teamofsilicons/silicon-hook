//! Linking IAM-era identities in Hook's data to Silicon Accounts uuids.
//!
//! Hook stored IAM public ids (`si:cos`, `c:alice`) in its identity columns.
//! Migration 0019 inventoried them in `hook_private.identity_links`. The
//! operator reviews a mapping file and applies it with
//! `hook-migrate link-identities --file mapping.csv [--dry-run]`, which in one
//! transaction records each link and fills the Accounts uuid columns of the
//! rows that hold a mapped IAM id. The IAM-era columns are never changed, so
//! re-running with a corrected file simply overwrites the uuid columns (and an
//! empty uuid unlinks an id).
//!
//! The file is CSV with a header: `iam_public_id,accounts_uuid`,
//! `iam_principal_id,accounts_uuid` (Hook's principal ids are its public ids),
//! or `iam_principal_id,iam_public_id,accounts_uuid`. Blank lines and lines
//! starting with `#` are ignored.

use std::collections::BTreeMap;

use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::domain::{AccountUuid, PublicId};

/// One validated line of a mapping file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MappingRow {
    /// The IAM-era public id as Hook stored it.
    pub iam_public_id: PublicId,
    /// The IAM principal id, when the file gives one separately.
    pub iam_principal_id: Option<String>,
    /// The Silicon Accounts uuid; `None` unlinks the id.
    pub accounts_uuid: Option<AccountUuid>,
}

/// A validated mapping file.
#[derive(Clone, Debug)]
pub struct IdentityMapping {
    /// Validated rows, in file order.
    pub rows: Vec<MappingRow>,
    /// SHA-256 of the file bytes, recorded as the source of every link.
    pub sha256: String,
}

/// Every problem in a mapping file, with line numbers.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct MappingErrors {
    /// One message per problem.
    pub errors: Vec<String>,
}

impl std::fmt::Display for MappingErrors {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            formatter,
            "the mapping file has {} problem(s):",
            self.errors.len()
        )?;
        for error in &self.errors {
            writeln!(formatter, "  {error}")?;
        }
        Ok(())
    }
}

impl std::error::Error for MappingErrors {}

#[derive(Clone, Copy)]
enum Layout {
    PublicId,
    PrincipalAndPublicId,
}

/// Parses and validates a mapping file. All problems are reported together.
///
/// # Errors
///
/// Returns every malformed line, unknown header, invalid id or uuid,
/// duplicated IAM id and uuid shared by two IAM ids.
pub fn parse_mapping(bytes: &[u8]) -> Result<IdentityMapping, MappingErrors> {
    let failed = |message: String| MappingErrors {
        errors: vec![message],
    };
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Err(failed("the file is not UTF-8 text".to_owned()));
    };
    let mut lines = text
        .lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line.trim()))
        .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'));
    let layout = parse_header(lines.next()).map_err(failed)?;
    let mut errors = Vec::new();
    let mut rows = Vec::new();
    let mut seen_ids: BTreeMap<String, usize> = BTreeMap::new();
    let mut seen_uuids: BTreeMap<String, (usize, String)> = BTreeMap::new();
    for (number, line) in lines {
        let row = match parse_row(layout, number, line) {
            Ok(row) => row,
            Err(message) => {
                errors.push(message);
                continue;
            }
        };
        let id = row.iam_public_id.as_str().to_owned();
        if let Some(first) = seen_ids.insert(id.clone(), number) {
            errors.push(format!(
                "line {number}: {id} is already mapped on line {first}"
            ));
            continue;
        }
        if let Some(uuid) = &row.accounts_uuid
            && let Some((first, other)) = seen_uuids.insert(uuid.as_str().to_owned(), (number, id))
        {
            errors.push(format!(
                "line {number}: {uuid} is also mapped to {other} on line {first}; \
                 one Silicon Accounts account cannot stand for two IAM identities"
            ));
            continue;
        }
        rows.push(row);
    }
    if !errors.is_empty() {
        return Err(MappingErrors { errors });
    }
    Ok(IdentityMapping {
        rows,
        sha256: hex::encode(Sha256::digest(bytes)),
    })
}

fn parse_header(line: Option<(usize, &str)>) -> Result<Layout, String> {
    match line {
        // Hook stored IAM principals by their public ids (`si:cos`), so the
        // shared `iam_principal_id,accounts_uuid` layout means the same thing.
        Some((_, "iam_public_id,accounts_uuid" | "iam_principal_id,accounts_uuid")) => {
            Ok(Layout::PublicId)
        }
        Some((_, "iam_principal_id,iam_public_id,accounts_uuid")) => {
            Ok(Layout::PrincipalAndPublicId)
        }
        Some((number, other)) => Err(format!(
            "line {number}: the header is `{other}`; use `iam_public_id,accounts_uuid` \
             or `iam_principal_id,iam_public_id,accounts_uuid`"
        )),
        None => Err("the file has no header and no rows".to_owned()),
    }
}

fn parse_row(layout: Layout, number: usize, line: &str) -> Result<MappingRow, String> {
    let fields = line.split(',').map(str::trim).collect::<Vec<_>>();
    let (principal, public, uuid) = match (layout, fields.as_slice()) {
        (Layout::PublicId, [public, uuid]) => (None, *public, *uuid),
        (Layout::PrincipalAndPublicId, [principal, public, uuid]) => (
            Some(*principal).filter(|value| !value.is_empty()),
            *public,
            *uuid,
        ),
        (Layout::PublicId, _) => {
            return Err(format!("line {number}: expected 2 comma-separated fields"));
        }
        (Layout::PrincipalAndPublicId, _) => {
            return Err(format!("line {number}: expected 3 comma-separated fields"));
        }
    };
    let Ok(iam_public_id) = PublicId::new(public) else {
        return Err(format!(
            "line {number}: `{public}` is not an IAM public id \
             (Hook stored ids like si:cos or c:alice)"
        ));
    };
    let accounts_uuid = if uuid.is_empty() {
        None
    } else {
        let Ok(uuid) = AccountUuid::new(uuid) else {
            return Err(format!(
                "line {number}: `{uuid}` is not a Silicon Accounts uuid \
                 (letters and digits, such as 8HV)"
            ));
        };
        Some(uuid)
    };
    if principal.is_some_and(|principal| principal.len() > 255) {
        return Err(format!(
            "line {number}: the IAM principal id is longer than 255 characters"
        ));
    }
    Ok(MappingRow {
        iam_public_id,
        iam_principal_id: principal.map(ToOwned::to_owned),
        accounts_uuid,
    })
}

/// Rows whose Accounts uuid columns one run filled or changed.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct RekeyedRows {
    /// Hooks whose owning Silicon was linked.
    pub hooks: u64,
    /// Hooks whose creator was linked.
    pub hook_creators: u64,
    /// Retained verified requests.
    pub events: u64,
    /// Retained blocked requests.
    pub blocked_requests: u64,
    /// Retired endpoint keys.
    pub retired_endpoint_keys: u64,
    /// Audit rows (owning Silicon).
    pub audit_silicons: u64,
    /// Audit rows (actor).
    pub audit_actors: u64,
}

/// What one `link-identities` run did (or would do, in a dry run).
#[derive(Clone, Debug, Serialize)]
pub struct LinkReport {
    /// Whether the transaction was rolled back.
    pub dry_run: bool,
    /// SHA-256 of the mapping file.
    pub mapping_sha256: String,
    /// Rows in the file.
    pub rows_in_file: usize,
    /// Rows that link an IAM id to an Accounts uuid.
    pub linked: usize,
    /// Rows that remove a link.
    pub unlinked: usize,
    /// Rows changed per table.
    pub rekeyed: RekeyedRows,
    /// Ids in the file that no Hook data references.
    pub not_in_hook_data: Vec<String>,
    /// IAM ids in Hook's data that still have no Accounts uuid after this run.
    pub unmatched_in_hook_data: Vec<String>,
    /// IAM-era hooks still without an owning Accounts Silicon (not reachable
    /// by management; their ingress URLs keep working).
    pub hooks_without_owner: i64,
    /// IAM-era observer bindings, which are not carried over (Carbons
    /// subscribe again).
    pub legacy_observer_bindings: i64,
}

/// Why a run was refused before changing anything.
#[derive(Debug)]
pub enum LinkError {
    /// An Accounts uuid in the file is already linked to an IAM id the file
    /// does not mention.
    Conflicts(Vec<String>),
    /// PostgreSQL failed.
    Database(sqlx::Error),
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflicts(conflicts) => {
                writeln!(
                    formatter,
                    "the mapping conflicts with links from earlier runs:"
                )?;
                for conflict in conflicts {
                    writeln!(formatter, "  {conflict}")?;
                }
                Ok(())
            }
            Self::Database(error) => write!(formatter, "database failure: {error}"),
        }
    }
}

impl std::error::Error for LinkError {}

impl From<sqlx::Error> for LinkError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

/// Immutable history tables whose triggers the run lifts inside its own
/// transaction to fill the new uuid columns (nothing else is written).
const IMMUTABLE: [(&str, &str); 4] = [
    ("hook.events", "events_are_immutable"),
    ("hook.blocked_requests", "blocked_requests_are_immutable"),
    (
        "hook_private.retired_endpoint_keys",
        "retired_endpoint_keys_are_immutable",
    ),
    ("hook_private.audit_log", "audit_log_is_append_only"),
];

/// Applies a mapping in one transaction (rolled back for a dry run).
///
/// Must run as the schema owner (the migrator role): it briefly disables the
/// immutability triggers of the history tables inside its transaction.
///
/// # Errors
///
/// Returns conflicts with earlier links, or a database failure; nothing is
/// changed then.
pub async fn link_identities(
    pool: &sqlx::PgPool,
    mapping: &IdentityMapping,
    dry_run: bool,
) -> Result<LinkReport, LinkError> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET LOCAL lock_timeout = '15s'")
        .execute(&mut *transaction)
        .await?;
    let ids = mapping
        .rows
        .iter()
        .map(|row| row.iam_public_id.as_str().to_owned())
        .collect::<Vec<_>>();
    let kinds = mapping
        .rows
        .iter()
        .map(|row| row.iam_public_id.kind().as_str().to_owned())
        .collect::<Vec<_>>();
    let principals = mapping
        .rows
        .iter()
        .map(|row| row.iam_principal_id.clone())
        .collect::<Vec<_>>();
    let uuids = mapping
        .rows
        .iter()
        .map(|row| {
            row.accounts_uuid
                .as_ref()
                .map(|uuid| uuid.as_str().to_owned())
        })
        .collect::<Vec<_>>();
    let conflicts = sqlx::query_as::<_, (String, String)>(
        "SELECT link.accounts_uuid, link.iam_public_id FROM hook_private.identity_links AS link
         WHERE link.accounts_uuid = ANY($1) AND NOT (link.iam_public_id = ANY($2))
         ORDER BY link.accounts_uuid",
    )
    .bind(&uuids)
    .bind(&ids)
    .fetch_all(&mut *transaction)
    .await?;
    if !conflicts.is_empty() {
        return Err(LinkError::Conflicts(
            conflicts
                .into_iter()
                .map(|(uuid, id)| {
                    format!(
                        "{uuid} is linked to {id} by an earlier run; add {id} to the file (with its correct uuid, or an empty uuid to unlink it)"
                    )
                })
                .collect(),
        ));
    }
    // Unlinks first, so a uuid can move from one id to another in one file.
    sqlx::query(
        "UPDATE hook_private.identity_links SET accounts_uuid = NULL, linked_at = NULL
         WHERE iam_public_id = ANY($1)",
    )
    .bind(&ids)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO hook_private.identity_links
             (iam_public_id, kind, iam_principal_id, accounts_uuid, linked_at, source)
         SELECT row.id, row.kind, row.principal, row.uuid,
                CASE WHEN row.uuid IS NULL THEN NULL ELSE clock_timestamp() END, $5
         FROM unnest($1::text[], $2::text[], $3::text[], $4::text[]) AS row(id, kind, principal, uuid)
         ON CONFLICT (iam_public_id) DO UPDATE SET
             iam_principal_id = COALESCE(EXCLUDED.iam_principal_id, identity_links.iam_principal_id),
             accounts_uuid = EXCLUDED.accounts_uuid,
             linked_at = EXCLUDED.linked_at,
             source = EXCLUDED.source",
    )
    .bind(&ids)
    .bind(&kinds)
    .bind(&principals)
    .bind(&uuids)
    .bind(format!("mapping:{}", mapping.sha256))
    .execute(&mut *transaction)
    .await?;
    for (table, trigger) in IMMUTABLE {
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "ALTER TABLE {table} DISABLE TRIGGER {trigger}"
        )))
        .execute(&mut *transaction)
        .await?;
    }
    let rekeyed = rekey(&mut transaction, &ids).await?;
    for (table, trigger) in IMMUTABLE {
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "ALTER TABLE {table} ENABLE TRIGGER {trigger}"
        )))
        .execute(&mut *transaction)
        .await?;
    }
    let report = report(&mut transaction, mapping, &ids, dry_run, rekeyed).await?;
    if dry_run {
        transaction.rollback().await?;
    } else {
        transaction.commit().await?;
    }
    Ok(report)
}

async fn rekey(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ids: &[String],
) -> Result<RekeyedRows, sqlx::Error> {
    let hooks = sqlx::query(
        "UPDATE hook.hooks AS hook SET silicon_uuid = link.accounts_uuid
         FROM hook_private.identity_links AS link
         WHERE hook.silicon_id = link.iam_public_id AND link.kind = 'silicon'
           AND link.iam_public_id = ANY($1)
           AND hook.silicon_uuid IS DISTINCT FROM link.accounts_uuid",
    )
    .bind(ids)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    let hook_creators = sqlx::query(
        "UPDATE hook.hooks AS hook SET created_by_uuid = link.accounts_uuid
         FROM hook_private.identity_links AS link
         WHERE hook.created_by_id = link.iam_public_id AND link.iam_public_id = ANY($1)
           AND hook.created_by_uuid IS DISTINCT FROM link.accounts_uuid",
    )
    .bind(ids)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    let mut history = Vec::new();
    for table in ["hook.events", "hook.blocked_requests"] {
        history.push(
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "UPDATE {table} AS record SET silicon_uuid = hook.silicon_uuid
                 FROM hook.hooks AS hook
                 WHERE record.hook_id = hook.id AND record.silicon_id = hook.silicon_id
                   AND record.silicon_id = ANY($1)
                   AND record.silicon_uuid IS DISTINCT FROM hook.silicon_uuid"
            )))
            .bind(ids)
            .execute(&mut **transaction)
            .await?
            .rows_affected(),
        );
    }
    let retired_endpoint_keys = sqlx::query(
        "UPDATE hook_private.retired_endpoint_keys AS retired SET silicon_uuid = link.accounts_uuid
         FROM hook_private.identity_links AS link
         WHERE retired.silicon_id = link.iam_public_id AND link.kind = 'silicon'
           AND link.iam_public_id = ANY($1)
           AND retired.silicon_uuid IS DISTINCT FROM link.accounts_uuid",
    )
    .bind(ids)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    let audit_silicons = sqlx::query(
        "UPDATE hook_private.audit_log AS audit SET silicon_uuid = link.accounts_uuid
         FROM hook_private.identity_links AS link
         WHERE audit.silicon_id = link.iam_public_id AND link.kind = 'silicon'
           AND link.iam_public_id = ANY($1)
           AND audit.silicon_uuid IS DISTINCT FROM link.accounts_uuid",
    )
    .bind(ids)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    let audit_actors = sqlx::query(
        "UPDATE hook_private.audit_log AS audit SET actor_uuid = link.accounts_uuid
         FROM hook_private.identity_links AS link
         WHERE audit.actor_id = link.iam_public_id AND link.iam_public_id = ANY($1)
           AND audit.actor_uuid IS DISTINCT FROM link.accounts_uuid",
    )
    .bind(ids)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    Ok(RekeyedRows {
        hooks,
        hook_creators,
        events: history[0],
        blocked_requests: history[1],
        retired_endpoint_keys,
        audit_silicons,
        audit_actors,
    })
}

async fn report(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mapping: &IdentityMapping,
    ids: &[String],
    dry_run: bool,
    rekeyed: RekeyedRows,
) -> Result<LinkReport, sqlx::Error> {
    let not_in_hook_data = sqlx::query_scalar::<_, String>(
        "SELECT id FROM unnest($1::text[]) AS mapped(id)
         WHERE NOT EXISTS (SELECT 1 FROM hook_private.identity_links AS link
                           WHERE link.iam_public_id = mapped.id AND link.source = 'inventory')
           AND NOT EXISTS (SELECT 1 FROM hook.hooks WHERE silicon_id = mapped.id OR created_by_id = mapped.id)
         ORDER BY id",
    )
    .bind(ids)
    .fetch_all(&mut **transaction)
    .await?;
    let unmatched_in_hook_data = sqlx::query_scalar::<_, String>(
        "SELECT iam_public_id FROM hook_private.identity_links
         WHERE accounts_uuid IS NULL ORDER BY iam_public_id",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let hooks_without_owner =
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM hook.hooks WHERE silicon_uuid IS NULL")
            .fetch_one(&mut **transaction)
            .await?;
    let legacy_observer_bindings =
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM hook_private.ting_recipient_bindings")
            .fetch_one(&mut **transaction)
            .await?;
    Ok(LinkReport {
        dry_run,
        mapping_sha256: mapping.sha256.clone(),
        rows_in_file: mapping.rows.len(),
        linked: mapping
            .rows
            .iter()
            .filter(|row| row.accounts_uuid.is_some())
            .count(),
        unlinked: mapping
            .rows
            .iter()
            .filter(|row| row.accounts_uuid.is_none())
            .count(),
        rekeyed,
        not_in_hook_data,
        unmatched_in_hook_data,
        hooks_without_owner,
        legacy_observer_bindings,
    })
}

#[cfg(test)]
mod tests {
    use super::{AccountUuid, parse_mapping};

    #[test]
    fn accepts_the_documented_layouts() -> Result<(), Box<dyn std::error::Error>> {
        let mapping = parse_mapping(b"# reviewed 2026-10-10\niam_public_id,accounts_uuid\nsi:cos, 8HV\nc:alice,zQo\nsi:old,\n")?;
        assert_eq!(mapping.rows.len(), 3);
        assert_eq!(
            mapping.rows[0]
                .accounts_uuid
                .as_ref()
                .map(AccountUuid::as_str),
            Some("8HV")
        );
        assert!(
            mapping.rows[2].accounts_uuid.is_none(),
            "an empty uuid unlinks"
        );
        assert_eq!(mapping.sha256.len(), 64);
        let with_principal =
            parse_mapping(b"iam_principal_id,iam_public_id,accounts_uuid\n0b9c-uuid,si:cos,8HV\n")?;
        assert_eq!(
            with_principal.rows[0].iam_principal_id.as_deref(),
            Some("0b9c-uuid")
        );
        assert!(parse_mapping(b"iam_principal_id,accounts_uuid\nsi:cos,8HV\n").is_ok());
        Ok(())
    }

    #[test]
    fn reports_every_problem_with_its_line() {
        let errors = parse_mapping(
            b"iam_public_id,accounts_uuid\ncos,8HV\nsi:a,not a uuid\nsi:b,8HV\nsi:c,8HV\nsi:b,zQo\nsi:d\n",
        )
        .err()
        .map(|errors| errors.errors)
        .unwrap_or_default();
        assert_eq!(errors.len(), 5, "{errors:?}");
        assert!(errors[0].starts_with("line 2: `cos` is not an IAM public id"));
        assert!(errors[1].starts_with("line 3: `not a uuid`"));
        assert!(errors[2].contains("8HV is also mapped to si:b on line 4"));
        assert!(errors[3].contains("si:b is already mapped on line 4"));
        assert!(errors[4].starts_with("line 7: expected 2"));
        assert!(parse_mapping(b"old,new\n").is_err());
        assert!(parse_mapping(b"").is_err());
    }
}
