/// This exception is raised when an invalid argument is supplied to a method.
#[derive(Debug, Clone, thiserror::Error)]
#[error("ArgumentError: {0}")]
pub struct ArgumentError(pub String);
