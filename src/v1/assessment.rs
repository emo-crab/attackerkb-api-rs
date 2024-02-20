use crate::v1::TagsOrReferences;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Assessment {
  pub id: Uuid,
  pub editor_id: Uuid,
  pub topic_id: Uuid,
  pub created: DateTime<Utc>,
  pub revision_date: DateTime<Utc>,
  pub document: String,
  pub score: i32,
  #[serde(default)]
  pub metadata: HashMap<String, i32>,
  pub tags: Vec<TagsOrReferences>,
}
