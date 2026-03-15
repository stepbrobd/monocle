//! Session-based SQLite stores for reconstructed RIB snapshots.
//!
//! These stores are separate from `MsgStore` because RIB reconstruction needs:
//! - route-identity keys with `path_id`
//! - exact `BgpElem` round-tripping for reconstructed RIB state
//! - merged SQLite output keyed by `rib_ts`

use anyhow::{anyhow, Result};
use bgpkit_parser::BgpElem;
use rusqlite::{params, OptionalExtension};
use serde_json::Value;
use tempfile::{NamedTempFile, TempPath};

use crate::database::core::DatabaseConn;

fn opt_to_sql_i64(v: Option<u32>) -> i64 {
    v.map(i64::from).unwrap_or(-1)
}

fn sql_i64_to_opt(v: i64) -> Option<u32> {
    if v < 0 {
        None
    } else {
        u32::try_from(v).ok()
    }
}

fn elem_as_path(elem: &BgpElem) -> Option<String> {
    elem.as_path.as_ref().map(|path| path.to_string())
}

fn elem_origin_asns(elem: &BgpElem) -> Option<String> {
    elem.origin_asns.as_ref().map(|asns| {
        asns.iter()
            .map(|asn| asn.to_string())
            .collect::<Vec<_>>()
            .join(" ")
    })
}

fn elem_next_hop(elem: &BgpElem) -> Option<String> {
    elem.next_hop.as_ref().map(|hop| hop.to_string())
}

fn elem_communities(elem: &BgpElem) -> Option<String> {
    elem.communities.as_ref().map(|communities| {
        communities
            .iter()
            .map(|community| community.to_string())
            .collect::<Vec<_>>()
            .join(" ")
    })
}

fn elem_origin(elem: &BgpElem) -> Option<String> {
    elem.origin.as_ref().map(|origin| origin.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RibRouteKey {
    pub collector: String,
    pub peer_ip: String,
    pub peer_asn: u32,
    pub prefix: String,
    pub path_id: Option<u32>,
}

impl RibRouteKey {
    pub fn from_elem(collector: &str, elem: &BgpElem) -> Self {
        Self {
            collector: collector.to_string(),
            peer_ip: elem.peer_ip.to_string(),
            peer_asn: elem.peer_asn.to_u32(),
            prefix: elem.prefix.prefix.to_string(),
            path_id: elem.prefix.path_id,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StoredRibEntry {
    pub collector: String,
    pub elem: BgpElem,
}

impl StoredRibEntry {
    pub fn new(collector: impl Into<String>, elem: BgpElem) -> Self {
        Self {
            collector: collector.into(),
            elem,
        }
    }

    pub fn route_key(&self) -> RibRouteKey {
        RibRouteKey::from_elem(&self.collector, &self.elem)
    }

    fn elem_json(&self) -> Result<String> {
        serde_json::to_string(&self.elem)
            .map_err(|e| anyhow!("Failed to serialize BgpElem for SQLite storage: {}", e))
    }

    fn from_row(row: &rusqlite::Row<'_>) -> Result<Self> {
        let collector: String = row
            .get("collector")
            .map_err(|e| anyhow!("Failed to read collector column: {}", e))?;
        let elem_json: String = row
            .get("elem_json")
            .map_err(|e| anyhow!("Failed to read elem_json column: {}", e))?;
        let elem = serde_json::from_str::<BgpElem>(&elem_json)
            .map_err(|e| anyhow!("Failed to deserialize stored BgpElem JSON: {}", e))?;
        Ok(Self { collector, elem })
    }
}

pub struct RibStateStore {
    db: DatabaseConn,
    _temp_path: Option<TempPath>,
}

impl RibStateStore {
    pub fn new(db_path: Option<&str>, reset: bool) -> Result<Self> {
        let db = DatabaseConn::open(db_path)?;
        let store = Self {
            db,
            _temp_path: None,
        };
        store.initialize(reset)?;
        Ok(store)
    }

    pub fn new_temp() -> Result<Self> {
        let file = NamedTempFile::new().map_err(|e| {
            anyhow!(
                "Failed to create temporary SQLite path for rib state: {}",
                e
            )
        })?;
        let temp_path = file.into_temp_path();
        let db = DatabaseConn::open_path(
            temp_path
                .to_str()
                .ok_or_else(|| anyhow!("Temporary rib state path contains invalid UTF-8"))?,
        )?;
        let store = Self {
            db,
            _temp_path: Some(temp_path),
        };
        store.initialize(true)?;
        Ok(store)
    }

    fn initialize(&self, reset: bool) -> Result<()> {
        if reset {
            self.db
                .conn
                .execute("DROP TABLE IF EXISTS rib_state", [])
                .map_err(|e| anyhow!("Failed to drop rib_state table: {}", e))?;
        }

        self.db
            .conn
            .execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS rib_state (
                    collector TEXT NOT NULL,
                    peer_ip TEXT NOT NULL,
                    peer_asn INTEGER NOT NULL,
                    prefix TEXT NOT NULL,
                    path_id INTEGER NOT NULL,
                    timestamp REAL NOT NULL,
                    as_path TEXT,
                    origin_asns TEXT,
                    origin TEXT,
                    next_hop TEXT,
                    local_pref INTEGER,
                    med INTEGER,
                    communities TEXT,
                    atomic INTEGER NOT NULL,
                    aggr_asn INTEGER,
                    aggr_ip TEXT,
                    elem_json TEXT NOT NULL,
                    PRIMARY KEY (collector, peer_ip, peer_asn, prefix, path_id)
                );
                CREATE INDEX IF NOT EXISTS idx_rib_state_collector ON rib_state(collector);
                CREATE INDEX IF NOT EXISTS idx_rib_state_peer_asn ON rib_state(peer_asn);
                CREATE INDEX IF NOT EXISTS idx_rib_state_prefix ON rib_state(prefix);
                "#,
            )
            .map_err(|e| anyhow!("Failed to initialize rib_state schema: {}", e))?;
        Ok(())
    }

    pub fn count(&self) -> Result<u64> {
        self.db.table_count("rib_state")
    }

    pub fn route_exists(&self, key: &RibRouteKey) -> Result<bool> {
        let exists = self
            .db
            .conn
            .query_row(
                "SELECT 1 FROM rib_state WHERE collector = ?1 AND peer_ip = ?2 AND peer_asn = ?3 AND prefix = ?4 AND path_id = ?5",
                params![
                    key.collector,
                    key.peer_ip,
                    key.peer_asn,
                    key.prefix,
                    opt_to_sql_i64(key.path_id),
                ],
                |_| Ok(()),
            )
            .optional()
            .map_err(|e| anyhow!("Failed to test route existence in rib_state: {}", e))?;
        Ok(exists.is_some())
    }

    pub fn upsert_entry(&self, entry: &StoredRibEntry) -> Result<()> {
        self.upsert_entries(std::slice::from_ref(entry))
    }

    pub fn upsert_entries(&self, entries: &[StoredRibEntry]) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }

        let tx = self
            .db
            .conn
            .unchecked_transaction()
            .map_err(|e| anyhow!("Failed to begin rib_state transaction: {}", e))?;
        let mut stmt = tx
            .prepare_cached(
                r#"
                INSERT OR REPLACE INTO rib_state (
                    collector, peer_ip, peer_asn, prefix, path_id, timestamp,
                    as_path, origin_asns, origin, next_hop, local_pref, med,
                    communities, atomic, aggr_asn, aggr_ip, elem_json
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
                "#,
            )
            .map_err(|e| anyhow!("Failed to prepare rib_state upsert statement: {}", e))?;

        for entry in entries {
            stmt.execute(params![
                entry.collector,
                entry.elem.peer_ip.to_string(),
                entry.elem.peer_asn.to_u32(),
                entry.elem.prefix.prefix.to_string(),
                opt_to_sql_i64(entry.elem.prefix.path_id),
                entry.elem.timestamp,
                elem_as_path(&entry.elem),
                elem_origin_asns(&entry.elem),
                elem_origin(&entry.elem),
                elem_next_hop(&entry.elem),
                entry.elem.local_pref,
                entry.elem.med,
                elem_communities(&entry.elem),
                if entry.elem.atomic { 1_i64 } else { 0_i64 },
                entry.elem.aggr_asn.map(|asn| asn.to_u32()),
                entry.elem.aggr_ip.as_ref().map(|ip| ip.to_string()),
                entry.elem_json()?,
            ])
            .map_err(|e| anyhow!("Failed to upsert entry into rib_state: {}", e))?;
        }

        drop(stmt);
        tx.commit()
            .map_err(|e| anyhow!("Failed to commit rib_state upserts: {}", e))?;
        Ok(())
    }

    pub fn delete_key(&self, key: &RibRouteKey) -> Result<()> {
        self.delete_keys(std::slice::from_ref(key))
    }

    pub fn delete_keys(&self, keys: &[RibRouteKey]) -> Result<()> {
        if keys.is_empty() {
            return Ok(());
        }

        let tx = self
            .db
            .conn
            .unchecked_transaction()
            .map_err(|e| anyhow!("Failed to begin rib_state delete transaction: {}", e))?;
        let mut stmt = tx
            .prepare_cached(
                "DELETE FROM rib_state WHERE collector = ?1 AND peer_ip = ?2 AND peer_asn = ?3 AND prefix = ?4 AND path_id = ?5",
            )
            .map_err(|e| anyhow!("Failed to prepare rib_state delete statement: {}", e))?;

        for key in keys {
            stmt.execute(params![
                key.collector,
                key.peer_ip,
                key.peer_asn,
                key.prefix,
                opt_to_sql_i64(key.path_id),
            ])
            .map_err(|e| anyhow!("Failed to delete entry from rib_state: {}", e))?;
        }

        drop(stmt);
        tx.commit()
            .map_err(|e| anyhow!("Failed to commit rib_state deletes: {}", e))?;
        Ok(())
    }

    pub fn visit_entries<F>(&self, mut visitor: F) -> Result<()>
    where
        F: FnMut(StoredRibEntry) -> Result<()>,
    {
        let mut stmt = self
            .db
            .conn
            .prepare(
                "SELECT collector, elem_json FROM rib_state ORDER BY collector, peer_asn, peer_ip, prefix, path_id",
            )
            .map_err(|e| anyhow!("Failed to prepare rib_state scan statement: {}", e))?;

        let mut rows = stmt
            .query([])
            .map_err(|e| anyhow!("Failed to query rib_state rows: {}", e))?;

        while let Some(row) = rows
            .next()
            .map_err(|e| anyhow!("Failed to iterate rib_state rows: {}", e))?
        {
            visitor(StoredRibEntry::from_row(row)?)?;
        }

        Ok(())
    }
}

pub struct RibSqliteStore {
    db: DatabaseConn,
}

impl RibSqliteStore {
    pub fn new(db_path: &str, reset: bool) -> Result<Self> {
        let db = DatabaseConn::open_path(db_path)?;
        let store = Self { db };
        store.initialize(reset)?;
        Ok(store)
    }

    fn initialize(&self, reset: bool) -> Result<()> {
        if reset {
            self.db
                .conn
                .execute("DROP TABLE IF EXISTS elems", [])
                .map_err(|e| anyhow!("Failed to drop existing rib output elems table: {}", e))?;
        }

        self.db
            .conn
            .execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS elems (
                    rib_ts INTEGER NOT NULL,
                    timestamp REAL NOT NULL,
                    collector TEXT NOT NULL,
                    peer_ip TEXT NOT NULL,
                    peer_asn INTEGER NOT NULL,
                    prefix TEXT NOT NULL,
                    path_id INTEGER NOT NULL,
                    as_path TEXT,
                    origin_asns TEXT,
                    origin TEXT,
                    next_hop TEXT,
                    local_pref INTEGER,
                    med INTEGER,
                    communities TEXT,
                    atomic INTEGER NOT NULL,
                    aggr_asn INTEGER,
                    aggr_ip TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_rib_output_rib_ts ON elems(rib_ts);
                CREATE INDEX IF NOT EXISTS idx_rib_output_rib_ts_prefix ON elems(rib_ts, prefix);
                CREATE INDEX IF NOT EXISTS idx_rib_output_rib_ts_peer_asn ON elems(rib_ts, peer_asn);
                CREATE INDEX IF NOT EXISTS idx_rib_output_rib_ts_collector ON elems(rib_ts, collector);
                "#,
            )
            .map_err(|e| anyhow!("Failed to initialize rib output SQLite schema: {}", e))?;
        Ok(())
    }

    pub fn insert_entry(&self, rib_ts: i64, entry: &StoredRibEntry) -> Result<()> {
        self.db
            .conn
            .execute(
                r#"
                INSERT INTO elems (
                    rib_ts, timestamp, collector, peer_ip, peer_asn, prefix, path_id,
                    as_path, origin_asns, origin, next_hop, local_pref, med,
                    communities, atomic, aggr_asn, aggr_ip
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
                "#,
                params![
                    rib_ts,
                    entry.elem.timestamp,
                    entry.collector,
                    entry.elem.peer_ip.to_string(),
                    entry.elem.peer_asn.to_u32(),
                    entry.elem.prefix.prefix.to_string(),
                    opt_to_sql_i64(entry.elem.prefix.path_id),
                    elem_as_path(&entry.elem),
                    elem_origin_asns(&entry.elem),
                    elem_origin(&entry.elem),
                    elem_next_hop(&entry.elem),
                    entry.elem.local_pref,
                    entry.elem.med,
                    elem_communities(&entry.elem),
                    if entry.elem.atomic { 1_i64 } else { 0_i64 },
                    entry.elem.aggr_asn.map(|asn| asn.to_u32()),
                    entry.elem.aggr_ip.as_ref().map(|ip| ip.to_string()),
                ],
            )
            .map_err(|e| anyhow!("Failed to insert entry into rib output SQLite store: {}", e))?;
        Ok(())
    }
}

pub fn elem_matches_stored_json(elem_json: &str, key: &str) -> Result<Option<Value>> {
    let value = serde_json::from_str::<Value>(elem_json)
        .map_err(|e| anyhow!("Failed to deserialize stored elem_json value: {}", e))?;
    Ok(value.get(key).cloned())
}

pub fn path_id_for_key(path_id: Option<u32>) -> i64 {
    opt_to_sql_i64(path_id)
}

pub fn path_id_from_key(path_id: i64) -> Option<u32> {
    sql_i64_to_opt(path_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bgpkit_parser::models::{AsPath, AsPathSegment, ElemType, NetworkPrefix};
    use std::net::{IpAddr, Ipv4Addr};

    fn test_elem() -> Result<BgpElem> {
        Ok(BgpElem {
            timestamp: 1234.0,
            elem_type: ElemType::ANNOUNCE,
            peer_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            peer_asn: 64496.into(),
            prefix: NetworkPrefix::new("203.0.113.0/24".parse()?, Some(7)),
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))),
            as_path: Some(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![64496.into(), 64497.into()])],
            }),
            origin_asns: Some(vec![64497.into()]),
            origin: None,
            local_pref: Some(100),
            med: Some(50),
            communities: None,
            atomic: false,
            aggr_asn: None,
            aggr_ip: None,
            only_to_customer: None,
            unknown: None,
            deprecated: None,
        })
    }

    #[test]
    fn test_rib_state_store_round_trip() -> Result<()> {
        let store = RibStateStore::new_temp()?;
        let entry = StoredRibEntry::new("rrc00", test_elem()?);
        store.upsert_entry(&entry)?;
        assert!(store.route_exists(&entry.route_key())?);

        let mut visited = Vec::new();
        store.visit_entries(|entry| {
            visited.push(entry);
            Ok(())
        })?;

        assert_eq!(visited.len(), 1);
        assert_eq!(visited[0].collector, "rrc00");
        assert_eq!(visited[0].elem.prefix.path_id, Some(7));
        Ok(())
    }

    #[test]
    fn test_path_id_helpers() {
        assert_eq!(path_id_for_key(None), -1);
        assert_eq!(path_id_from_key(-1), None);
        assert_eq!(path_id_from_key(42), Some(42));
    }

    #[test]
    fn test_elem_json_access() -> Result<()> {
        let elem = test_elem()?;
        let entry = StoredRibEntry::new("rrc00", elem);
        let origin_asns = elem_matches_stored_json(&entry.elem_json()?, "origin_asns")?;
        assert!(origin_asns.is_some());
        Ok(())
    }
}
