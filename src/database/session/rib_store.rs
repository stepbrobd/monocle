//! Working-state storage and SQLite export for reconstructed RIB snapshots.

use std::collections::HashMap;
use std::net::IpAddr;

use anyhow::{anyhow, Result};
use bgpkit_parser::BgpElem;
use rusqlite::params;

use crate::database::core::DatabaseConn;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RibRouteKey {
    pub collector: String,
    pub peer_ip: IpAddr,
    pub peer_asn: u32,
    pub prefix: String,
    pub path_id: Option<u32>,
}

impl RibRouteKey {
    pub fn from_elem(collector: &str, elem: &BgpElem) -> Self {
        Self {
            collector: collector.to_string(),
            peer_ip: elem.peer_ip,
            peer_asn: elem.peer_asn.to_u32(),
            prefix: elem.prefix.prefix.to_string(),
            path_id: elem.prefix.path_id,
        }
    }

    pub fn from_entry(entry: &StoredRibEntry) -> Self {
        Self {
            collector: entry.collector.clone(),
            peer_ip: entry.peer_ip,
            peer_asn: entry.peer_asn,
            prefix: entry.prefix.clone(),
            path_id: entry.path_id,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StoredRibEntry {
    pub collector: String,
    pub timestamp: f64,
    pub peer_ip: IpAddr,
    pub peer_asn: u32,
    pub prefix: String,
    pub path_id: Option<u32>,
    pub as_path: Option<String>,
    pub origin_asns: Option<Vec<u32>>,
}

impl StoredRibEntry {
    pub fn from_elem(collector: &str, elem: BgpElem) -> Self {
        Self {
            collector: collector.to_string(),
            timestamp: elem.timestamp,
            peer_ip: elem.peer_ip,
            peer_asn: elem.peer_asn.to_u32(),
            prefix: elem.prefix.prefix.to_string(),
            path_id: elem.prefix.path_id,
            as_path: elem.as_path.map(|path| path.to_string()),
            origin_asns: elem
                .origin_asns
                .map(|asns| asns.into_iter().map(|asn| asn.to_u32()).collect::<Vec<_>>()),
        }
    }

    pub fn route_key(&self) -> RibRouteKey {
        RibRouteKey::from_entry(self)
    }

    pub fn origin_asns_string(&self) -> Option<String> {
        self.origin_asns.as_ref().map(|asns| {
            asns.iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(" ")
        })
    }
}

pub struct RibStateStore {
    entries: HashMap<RibRouteKey, StoredRibEntry>,
}

impl RibStateStore {
    pub fn new_temp() -> Result<Self> {
        Ok(Self {
            entries: HashMap::new(),
        })
    }

    pub fn count(&self) -> Result<u64> {
        Ok(self.entries.len() as u64)
    }

    pub fn route_exists(&self, key: &RibRouteKey) -> Result<bool> {
        Ok(self.entries.contains_key(key))
    }

    pub fn upsert_entry(&mut self, entry: StoredRibEntry) -> Result<()> {
        self.upsert_entries(vec![entry])
    }

    pub fn upsert_entries<I>(&mut self, entries: I) -> Result<()>
    where
        I: IntoIterator<Item = StoredRibEntry>,
    {
        for entry in entries {
            self.entries.insert(entry.route_key(), entry);
        }
        Ok(())
    }

    pub fn delete_key(&mut self, key: &RibRouteKey) -> Result<()> {
        self.entries.remove(key);
        Ok(())
    }

    pub fn delete_keys<I>(&mut self, keys: I) -> Result<()>
    where
        I: IntoIterator<Item = RibRouteKey>,
    {
        for key in keys {
            self.entries.remove(&key);
        }
        Ok(())
    }

    pub fn visit_entries<F>(&self, mut visitor: F) -> Result<()>
    where
        F: FnMut(&StoredRibEntry) -> Result<()>,
    {
        let mut entries = self.entries.values().collect::<Vec<_>>();
        entries.sort_by(|a, b| {
            a.collector
                .cmp(&b.collector)
                .then(a.peer_asn.cmp(&b.peer_asn))
                .then(a.peer_ip.to_string().cmp(&b.peer_ip.to_string()))
                .then(a.prefix.cmp(&b.prefix))
                .then(a.path_id.cmp(&b.path_id))
        });

        for entry in entries {
            visitor(entry)?;
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
                    as_path TEXT,
                    origin_asns TEXT
                );
                "#,
            )
            .map_err(|e| anyhow!("Failed to initialize rib output SQLite schema: {}", e))?;
        Ok(())
    }

    pub fn insert_snapshot(&mut self, rib_ts: i64, state_store: &RibStateStore) -> Result<()> {
        let tx = self
            .db
            .conn
            .unchecked_transaction()
            .map_err(|e| anyhow!("Failed to begin rib output transaction: {}", e))?;
        let mut stmt = tx
            .prepare_cached(
                r#"
                INSERT INTO elems (
                    rib_ts, timestamp, collector, peer_ip, peer_asn, prefix, as_path, origin_asns
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                "#,
            )
            .map_err(|e| anyhow!("Failed to prepare rib output insert statement: {}", e))?;

        state_store.visit_entries(|entry| {
            stmt.execute(params![
                rib_ts,
                entry.timestamp,
                entry.collector,
                entry.peer_ip.to_string(),
                entry.peer_asn,
                entry.prefix,
                entry.as_path,
                entry.origin_asns_string(),
            ])
            .map_err(|e| anyhow!("Failed to insert entry into rib output SQLite store: {}", e))?;
            Ok(())
        })?;

        drop(stmt);
        tx.commit()
            .map_err(|e| anyhow!("Failed to commit rib output inserts: {}", e))?;
        Ok(())
    }

    pub fn finalize_indexes(&self) -> Result<()> {
        self.db
            .conn
            .execute_batch(
                r#"
                CREATE INDEX IF NOT EXISTS idx_rib_output_rib_ts ON elems(rib_ts);
                CREATE INDEX IF NOT EXISTS idx_rib_output_rib_ts_prefix ON elems(rib_ts, prefix);
                CREATE INDEX IF NOT EXISTS idx_rib_output_rib_ts_peer_asn ON elems(rib_ts, peer_asn);
                CREATE INDEX IF NOT EXISTS idx_rib_output_rib_ts_collector ON elems(rib_ts, collector);
                "#,
            )
            .map_err(|e| anyhow!("Failed to create rib output SQLite indexes: {}", e))?;
        Ok(())
    }
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
        let mut store = RibStateStore::new_temp()?;
        let entry = StoredRibEntry::from_elem("rrc00", test_elem()?);
        store.upsert_entry(entry.clone())?;
        assert!(store.route_exists(&entry.route_key())?);

        let mut visited = Vec::new();
        store.visit_entries(|entry| {
            visited.push(entry.clone());
            Ok(())
        })?;

        assert_eq!(visited.len(), 1);
        assert_eq!(visited[0].collector, "rrc00");
        assert_eq!(visited[0].path_id, Some(7));
        Ok(())
    }
}
