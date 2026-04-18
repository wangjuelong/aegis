use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("channel bootstrap failed: {0}")]
    ChannelBootstrap(String),
}

