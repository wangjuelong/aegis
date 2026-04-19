CREATE TABLE IF NOT EXISTS active_config (
    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    conf_version INTEGER NOT NULL,
    policy_bundle_version INTEGER NOT NULL,
    ruleset_revision INTEGER NOT NULL,
    model_revision INTEGER NOT NULL,
    config_toml TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS config_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conf_version INTEGER NOT NULL,
    config_toml TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS policy_state (
    bundle_version INTEGER NOT NULL,
    ruleset_revision INTEGER NOT NULL,
    model_revision INTEGER NOT NULL,
    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
