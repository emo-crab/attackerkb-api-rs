//! Paging management for unified API response
use crate::error::ErrorResponse;
use crate::v1::assessment::Assessment;
use crate::v1::contributor::Contributor;
use crate::v1::topic::Topic;

use serde::{Deserialize, Serialize};

pub(crate) fn default_size() -> i32 {
  10
}

/// The API returns seven primary objects in the body of the response: [KBResponse]
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum KBResponse {
  Topics(ListResponse<Topic>),
  Topic(SingleResponse<Topic>),
  Assessments(ListResponse<Assessment>),
  Assessment(SingleResponse<Assessment>),
  Contributors(ListResponse<Contributor>),
  Contributor(SingleResponse<Contributor>),
  Error(ErrorResponse),
}
/// There are multiple pages of data
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct ListResponse<T> {
  /// List
  pub data: Vec<T>,
  /// Pagination
  pub links: Option<Links>,
}
/// Single instance object
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct SingleResponse<T> {
  /// Single
  pub data: T,
}

/// Pagination links objects
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Links {
  /// resultsPerPage
  pub next: Option<Link>,
  /// startIndex
  pub prev: Option<Link>,
  /// totalResults
  #[serde(rename = "self")]
  pub self_field: Link,
}

/// Pagination link object
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Link {
  /// URL for paginated resource
  href: String,
}
