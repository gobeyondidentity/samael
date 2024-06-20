// use thiserror::Error;

#[derive(Debug, Clone, thiserror::Error)]
pub enum SchemaError {
    #[error("Missing encryption template from {0}")]
    MissingEncryptionTemplate(String),
}
