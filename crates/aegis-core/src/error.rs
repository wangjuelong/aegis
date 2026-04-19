use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("channel bootstrap failed: {0}")]
    ChannelBootstrap(String),

    #[error("config io failed: {0}")]
    ConfigIo(#[from] std::io::Error),

    #[error("config parse failed: {0}")]
    ConfigParse(#[from] toml::de::Error),

    #[error("config serialize failed: {0}")]
    ConfigSerialize(#[from] toml::ser::Error),

    #[error("json serialization failed: {0}")]
    Json(#[from] serde_json::Error),

    #[error("sqlite failed: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("cryptography failed: {0}")]
    Crypto(String),

    #[error("unsupported config version: {found}, supported range: {min_supported}-{current}")]
    UnsupportedConfigVersion {
        found: u32,
        min_supported: u32,
        current: u32,
    },
}
