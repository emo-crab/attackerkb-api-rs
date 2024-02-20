//! AttackerKB api error

use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

/// All Error enum
#[derive(Debug, thiserror::Error)]
pub enum Error {
  #[error("Invalid AttackerKB API Token: {}", source)]
  InvalidApiToken {
    source: reqwest::header::InvalidHeaderValue,
  },

  #[error("Unable to build reqwest HTTP client: {}", source)]
  BuildingClient { source: reqwest::Error },

  #[error("Error sending HTTP request: {}", source)]
  RequestFailed {
    #[from]
    source: reqwest::Error,
  },
  #[error("Error reading response: {}", source)]
  ResponseIo { source: reqwest::Error },

  #[error("API Error ({}): {}", .error.status, .error.message)]
  Api { error: ErrorResponse },
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash)]
#[serde(untagged)]
pub enum StatusCode {
  NonZeroU16(u16),
  String(String),
}

impl Display for StatusCode {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    let v = match self {
      StatusCode::NonZeroU16(n) => n.to_string(),
      StatusCode::String(s) => s.to_string(),
    };
    write!(f, "{}", v)
  }
}

/// Return [ErrorResponse] when API request encounters an error
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct ErrorResponse {
  /// A short description of the error that occurred.
  /// example: An error occurred while creating the record.
  pub message: String,
  /// The HTTP status code of the response.
  /// example: 500
  pub status: StatusCode,
}
