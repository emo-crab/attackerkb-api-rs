//! v1 version api
pub mod assessment;
pub mod contributor;
pub mod query;
pub mod topic;

use chrono::NaiveDateTime;
#[cfg(feature = "nvd-cves")]
use nvd_cves::impact::ImpactMetrics;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
#[serde(untagged)]
pub enum TagsOrReferences {
  FoldedRecord(FoldedRecord),
  References(References),
  Tags(Tags),
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct References {
  /// example: c0f010fe-da9c-4aa6-b898-c57d483df51b
  /// The UUID of the tag.
  pub id: Uuid,
  /// example: c28a806c-84c7-44bf-95d3-1241475de5bf
  /// The UUID of the contributor who last edited the topic.
  pub editor_id: Uuid,
  /// example: 2019-07-02T16:22:15.879357Z
  /// The date and time the reference was created.
  pub created: NaiveDateTime,
  /// example: CVE-2019-0708 - BlueKeep
  /// The name of the reference.
  pub name: String,
  /// example: <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-123-1342>
  /// The url associated with the reference.
  pub url: String,
  /// example: canonical
  /// The type of the reference.
  pub ref_type: String,
  /// example: system
  pub ref_source: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Tags {
  /// example: 9d2d9df6-cd8e-4ad2-82e7-e12b0678c9d9
  /// The UUID of the tag.
  pub id: Uuid,
  /// example: Common in enterprise
  /// The name of the tag. This is what shows up in the UI.
  pub name: String,
  /// example: common
  /// The type of the tag.
  pub r#type: String,
  /// example: common_enterprise
  /// The code of the tag used to reference tags.
  pub code: String,
  /// A JSON value containing key/value pairs describing various attributes about this tag.
  pub metadata: TagMetaData,
}

/// A JSON value containing key/value pairs describing various attributes about this tag.
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TagMetaData {
  /// example: high
  /// The value of the tag
  pub value: String,
  /// example: system
  /// The origination of where the tag was created
  pub source: String,
  /// example: TA0001
  /// The Mitre tactic ID.
  pub tactic_id: String,
  /// example: Initial Access
  /// The Mitre tactic name.
  pub tactic_name: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Score {
  /// The attacker value score.
  pub attacker_value: f32,
  /// The exploitability score.
  pub exploitability: f32,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct MetaData {
  #[serde(default)]
  pub configurations: Vec<String>,
  #[serde(default)]
  pub credits: Option<Credits>,
  #[serde(default)]
  pub cve_state: CveState,
  #[cfg(feature = "nvd-cves")]
  #[serde(flatten)]
  pub cvss_metric_v31: ImpactMetrics,
  #[serde(default)]
  pub references: Vec<String>,
  #[serde(default)]
  pub vendor: Option<Vendor>,
  #[serde(rename = "vulnerable-versions")]
  pub vulnerable_versions: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Vendor {
  #[serde(default)]
  product_names: Vec<String>,
  #[serde(default)]
  vendor_names: Vec<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub enum CveState {
  PUBLIC,
  RESERVED,
}

impl Default for CveState {
  fn default() -> Self {
    Self::PUBLIC
  }
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Default)]
#[serde(rename_all = "kebab-case")]
pub struct Credits {
  #[serde(default)]
  pub discovered_by: Vec<String>,
  pub module: Vec<String>,
}

/// Condensed version of a related object. The returned attributes are reduced as not to cause noise with the parent object. These full objects can be returned by specifying their type in the expand parameter.
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FoldedRecord {
  /// The primary UUID of the related object. This can be used in a subsequent request to the appropriate URL to retrieve the full object.
  pub id: Uuid,
}
