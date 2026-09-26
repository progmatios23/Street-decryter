use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io reading {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("unsupported or corrupt image: {0}")]
    Format(String),
    #[error(transparent)]
    Goblin(#[from] goblin::error::Error),
}
