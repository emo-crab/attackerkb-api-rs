use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Contributor {
  pub id: Uuid,
  pub username: String,
  pub avatar: Option<String>,
  pub created: DateTime<Utc>,
  pub score: i32,
}
