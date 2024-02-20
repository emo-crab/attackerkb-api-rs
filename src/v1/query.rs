use crate::pagination::default_size;
use chrono::NaiveDate;
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Builder)]
#[builder(setter(into), default)]
pub struct TopicsParameters {
  /// The UUID of a specific topic to return.
  /// Example: c0f010fe-da9c-4aa6-b898-c57d483df51b
  pub id: Option<Uuid>,
  /// The UUID of a contributor.
  /// Example: c28a806c-84c7-44bf-95d3-1241475de5bf
  pub editor_id: Option<Uuid>,
  /// Text to query the name attribute. A substring match is performed
  /// Example: bluekeep
  pub name: Option<String>,
  /// Return all topics that were created on the given date.
  /// Example: 2019-07-04
  pub created: Option<NaiveDate>,
  /// Return all topics that were created after the given date.
  /// Example: 2019-07-04
  pub created_after: Option<NaiveDate>,
  /// Return all topics that were created before the given date.
  /// Example: 2019-07-04
  pub created_before: Option<NaiveDate>,
  /// Return all topics that were last edited on the given date.
  /// Example: 2019-07-04
  pub revision_date: Option<NaiveDate>,
  /// Return all topics that were last edited after the given date.
  /// Example: 2019-07-04
  pub revised_after: Option<NaiveDate>,
  /// Return all topics that were last edited before the given date.
  /// Example: 2019-07-04
  pub revised_before: Option<NaiveDate>,
  /// Return all topics that were disclosed on the given date.
  /// Example: 2019-07-04
  pub disclosure_date: Option<NaiveDate>,
  /// Text to query the document attribute. A substring match is performed
  /// Example : RDP
  pub document: Option<String>,
  /// Text to query the metadata attribute. A substring match is performed
  /// Example : metasploit
  pub metadata: Option<String>,
  /// Return all topics that are featured.
  pub featured: Option<bool>,
  /// Return all topics where the rapid7Analysis was created on the given date.
  /// Example: 2019-07-04
  pub rapid7_analysis_created: Option<NaiveDate>,
  /// Return all topics where the rapid7Analysis was created after the given date.
  /// Example: 2019-07-04
  pub rapid7_analysis_created_after: Option<NaiveDate>,
  /// Return all topics where the rapid7Analysis was created before the given date.
  /// Example: 2019-07-04
  pub rapid7_analysis_created_before: Option<NaiveDate>,
  /// Return all topics where the rapid7Analysis was last edited on the given date.
  /// Example: 2019-07-04
  pub rapid7_analysis_revision_date: Option<NaiveDate>,
  /// Return all topics where the rapid7Analysis was last edited after the given date.
  /// Example: 2019-07-04
  pub rapid7_analysis_revised_after: Option<NaiveDate>,
  /// Return all topics where the rapid7Analysis was last edited before the given date.
  /// Example: 2019-07-04
  pub rapid7_analysis_revised_before: Option<NaiveDate>,
  /// Return all topics that have content that matches the query string q.
  /// Example : eternal blue
  pub q: Option<String>,
  /// Pagination page number.
  /// Default value : 0
  #[serde(default)]
  pub page: i32,
  /// The number of topics returned per page.
  /// Default value : 10
  #[serde(default = "default_size")]
  pub size: i32,
  pub sort: Option<String>,
  pub expand: Option<String>,
}

impl Default for TopicsParameters {
  fn default() -> Self {
    Self {
      id: None,
      editor_id: None,
      name: None,
      created: None,
      created_after: None,
      created_before: None,
      revision_date: None,
      revised_after: None,
      revised_before: None,
      disclosure_date: None,
      document: None,
      metadata: None,
      featured: None,
      rapid7_analysis_created: None,
      rapid7_analysis_created_after: None,
      rapid7_analysis_created_before: None,
      rapid7_analysis_revision_date: None,
      rapid7_analysis_revised_after: None,
      rapid7_analysis_revised_before: None,
      q: None,
      page: 0,
      size: 10,
      sort: None,
      expand: None,
    }
  }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Builder)]
#[builder(setter(into), default)]
pub struct AssessmentsParameters {
  /// The UUID of a specific assessment to return.
  /// Example: c0f010fe-da9c-4aa6-b898-c57d483df51b
  pub id: Option<Uuid>,
  /// The UUID of a contributor.
  /// Example: c28a806c-84c7-44bf-95d3-1241475de5bf
  pub editor_id: Option<Uuid>,
  /// The UUID of the topic this assessment was based on.
  /// Example: c28a806c-84c7-44bf-95d3-1241475de5bf
  pub topic_id: Option<Uuid>,
  /// Return all assessments that were created on the given date.
  /// Example: 2019-07-04
  pub created: Option<NaiveDate>,
  /// Return all assessments that were created after the given date.
  /// Example: 2019-07-04
  pub created_after: Option<NaiveDate>,
  /// Return all assessments that were created before the given date.
  /// Example: 2019-07-04
  pub created_before: Option<NaiveDate>,
  /// Return all assessments that were last edited on the given date.
  /// Example: 2019-07-04
  pub revision_date: Option<NaiveDate>,
  /// Return all assessments that were last edited after the given date.
  /// Example: 2019-07-04
  pub revised_after: Option<NaiveDate>,
  /// Return all assessments that were last edited before the given date.
  /// Example: 2019-07-04
  pub revised_before: Option<NaiveDate>,
  /// Return all topics that were disclosed on the given date.
  /// Example: 2019-07-04
  pub document: Option<String>,
  /// Return all assessments with this score.
  pub score: Option<i32>,
  /// Text to query the metadata attribute. A substring match is performed
  /// Example : metasploit
  pub metadata: Option<String>,
  /// Return all assessments that have content that matches the query string q.
  pub q: Option<String>,
  /// Pagination page number.
  /// Default value : 0
  #[serde(default)]
  pub page: i32,
  /// The number of topics returned per page.
  /// Default value : 10
  #[serde(default = "default_size")]
  pub size: i32,
  /// Sort by assessment attribute. This parameter takes the form attribute:order.
  /// attribute: id, editorId, created, revisionDate, document, score, metadata
  /// order: asc (ascending), desc (descending)
  /// Each attribute is sorted by its respective type.
  pub sort: Option<String>,
  /// Comma separated list of related objects to fully expand in the returned result. Only the id of related objects will be included if this parameter is not specified.
  pub expand: Option<String>,
}

impl Default for AssessmentsParameters {
  fn default() -> Self {
    Self {
      id: None,
      editor_id: None,
      topic_id: None,
      created: None,
      created_after: None,
      created_before: None,
      revision_date: None,
      revised_after: None,
      revised_before: None,
      document: None,
      score: None,
      metadata: None,
      q: None,
      page: 0,
      size: 10,
      sort: None,
      expand: None,
    }
  }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Builder)]
#[builder(setter(into), default)]
pub struct ContributorsParameters {
  /// The UUID of a specific contributor to return.
  /// Example: c0f010fe-da9c-4aa6-b898-c57d483df51b
  pub id: Option<Uuid>,
  /// Return contributors with the matching username.
  /// Example: c28a806c-84c7-44bf-95d3-1241475de5bf
  pub username: Option<String>,
  /// Return all contributors where avatar matches the given value.
  /// Example: c28a806c-84c7-44bf-95d3-1241475de5bf
  pub avatar: Option<Uuid>,
  /// Return all contributors that were created on the given date.
  /// Example: 2019-07-04
  pub created: Option<NaiveDate>,
  /// Return all contributors that were created after the given date.
  /// Example: 2019-07-04
  pub created_after: Option<NaiveDate>,
  /// Return all contributors that were created before the given date.
  /// Example: 2019-07-04
  pub created_before: Option<NaiveDate>,
  /// Return all contributors with this score.
  pub score: Option<i32>,
  /// Return all contributors that have usernames that match the query string q.
  pub q: Option<String>,
  /// Pagination page number.
  /// Default value : 0
  #[serde(default)]
  pub page: i32,
  /// The number of topics returned per page.
  /// Default value : 10
  #[serde(default = "default_size")]
  pub size: i32,
  /// Sort by contributor attribute. This parameter takes the form attribute:order.
  /// attribute: id, username, avatar, created, score.
  /// order: asc (ascending), desc (descending)
  /// Each attribute is sorted by its respective type.
  pub sort: Option<String>,
}

impl Default for ContributorsParameters {
  fn default() -> Self {
    Self {
      id: None,
      username: None,
      avatar: None,
      created: None,
      created_after: None,
      created_before: None,
      score: None,
      q: None,
      page: 0,
      size: 10,
      sort: None,
    }
  }
}
