use crate::config::AgentConfig;
use crate::error::CoreError;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

pub const AGENT_DB_NAME: &str = "agent.db";
pub const CURRENT_SCHEMA_VERSION: i64 = 1;
pub const MIN_READER_SCHEMA_VERSION: i64 = 1;

#[derive(Clone, Debug)]
pub struct Migration {
    pub version: i64,
    pub name: &'static str,
    pub sql: &'static str,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MigrationSummary {
    pub current_version: i64,
    pub applied_versions: Vec<i64>,
}

const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "agent_base",
    sql: include_str!("../migrations/0001_agent_base.sql"),
}];

pub struct AgentDb {
    conn: Connection,
}

impl AgentDb {
    pub fn open(path: &Path) -> Result<Self, CoreError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path)?;
        let db = Self { conn };
        db.bootstrap_metadata_tables()?;
        db.bootstrap_static_metadata()?;
        Ok(db)
    }

    pub fn current_version(&self) -> Result<i64, CoreError> {
        let version = self.conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        Ok(version)
    }

    pub fn metadata(&self, key: &str) -> Result<Option<String>, CoreError> {
        let value = self
            .conn
            .query_row(
                "SELECT value FROM schema_metadata WHERE key = ?1",
                [key],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        Ok(value)
    }

    pub fn apply_migrations(&mut self) -> Result<MigrationSummary, CoreError> {
        let mut summary = MigrationSummary {
            current_version: self.current_version()?,
            applied_versions: Vec::new(),
        };

        for migration in MIGRATIONS {
            if migration.version <= summary.current_version {
                continue;
            }

            self.conn.execute_batch(migration.sql)?;
            self.conn.execute(
                "INSERT INTO schema_migrations (version, name) VALUES (?1, ?2)",
                params![migration.version, migration.name],
            )?;
            self.set_metadata("schema_version", &migration.version.to_string())?;

            summary.current_version = migration.version;
            summary.applied_versions.push(migration.version);
        }

        Ok(summary)
    }

    pub fn sync_active_config(&self, config: &AgentConfig) -> Result<(), CoreError> {
        let raw = config.to_toml_string()?;
        self.conn.execute(
            r#"
            INSERT INTO active_config (
                singleton_id,
                conf_version,
                policy_bundle_version,
                ruleset_revision,
                model_revision,
                config_toml
            )
            VALUES (1, ?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(singleton_id) DO UPDATE SET
                conf_version = excluded.conf_version,
                policy_bundle_version = excluded.policy_bundle_version,
                ruleset_revision = excluded.ruleset_revision,
                model_revision = excluded.model_revision,
                config_toml = excluded.config_toml,
                updated_at = CURRENT_TIMESTAMP
            "#,
            params![
                config.conf_version,
                config.policy_version.policy_bundle,
                config.policy_version.ruleset_revision,
                config.policy_version.model_revision,
                raw,
            ],
        )?;
        self.conn.execute(
            "INSERT INTO config_snapshots (conf_version, config_toml) VALUES (?1, ?2)",
            params![config.conf_version, raw],
        )?;
        self.set_metadata("conf_version", &config.conf_version.to_string())?;
        Ok(())
    }

    fn bootstrap_metadata_tables(&self) -> Result<(), CoreError> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS schema_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            "#,
        )?;
        Ok(())
    }

    fn bootstrap_static_metadata(&self) -> Result<(), CoreError> {
        self.set_metadata("db_name", AGENT_DB_NAME)?;
        self.set_metadata("schema_version", &self.current_version()?.to_string())?;
        self.set_metadata(
            "min_reader_schema_version",
            &MIN_READER_SCHEMA_VERSION.to_string(),
        )?;
        if self.metadata("conf_version")?.is_none() {
            self.set_metadata("conf_version", "0")?;
        }
        Ok(())
    }

    fn set_metadata(&self, key: &str, value: &str) -> Result<(), CoreError> {
        self.conn.execute(
            r#"
            INSERT INTO schema_metadata (key, value)
            VALUES (?1, ?2)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = CURRENT_TIMESTAMP
            "#,
            params![key, value],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{AgentDb, CURRENT_SCHEMA_VERSION};
    use crate::config::{AgentConfig, CURRENT_CONF_VERSION};
    use uuid::Uuid;

    #[test]
    fn applies_schema_migrations_and_persists_config_version() {
        let db_path = std::env::temp_dir().join(format!("aegis-agent-{}.db", Uuid::now_v7()));
        let mut db = AgentDb::open(&db_path).expect("open agent db");

        let summary = db.apply_migrations().expect("apply migrations");
        assert_eq!(summary.current_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(
            db.current_version().expect("read version"),
            CURRENT_SCHEMA_VERSION
        );

        let config = AgentConfig::default();
        db.sync_active_config(&config).expect("sync config");
        let expected_conf_version = CURRENT_CONF_VERSION.to_string();

        assert_eq!(
            db.metadata("conf_version")
                .expect("read conf version")
                .as_deref(),
            Some(expected_conf_version.as_str())
        );
        assert_eq!(
            db.metadata("db_name").expect("read db name").as_deref(),
            Some("agent.db")
        );

        std::fs::remove_file(db_path).ok();
    }
}
