use crate::v1::{MetaData, Score, TagsOrReferences};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Topic {
  /// example: c0f010fe-da9c-4aa6-b898-c57d483df51b
  /// The UUID of the topic.
  pub id: Uuid,
  /// example: c28a806c-84c7-44bf-95d3-1241475de5bf
  /// The UUID of the contributor who last edited the topic.
  pub editor_id: Uuid,
  /// example: CVE-2019-0708 - BlueKeep
  /// The name or title of the topic.
  pub name: String,
  /// example: 2019-07-02T16:22:15.879357Z
  /// The date and time the topic was created.
  pub created: DateTime<Utc>,
  /// example: 2019-07-02T22:13:15.779501Z
  /// The date and time the topic was last changed.
  pub revision_date: DateTime<Utc>,
  /// example: 2019-11-07T22:53:05.779501Z
  /// The date and time the topic was disclosed.
  pub disclosure_date: Option<DateTime<Utc>>,
  /// example: A bug in Windows Remote Desktop protocol allows unauthenticated users to run arbitrary code via a specially crafted request to the service. This affects Windows 7/Windows Server 2008 and earlier releases. Given the ubiquity of RDP in corporate environments and the trusted nature of RDP, this could pose serious concerns for ransomware attacks much like WannaCry. Patches are released for Windows 7/2008 Operating systems as well as Windows XP.
  /// The main content of the topic. This content will be rendered in the UI using Markdown.
  pub document: String,
  /// example: { "references": [ "<https://support.microsoft.com/en-us/help/4499164/windows-7-update-kb4499164>", "<https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708>", "CVE-2019-0708", "<https://www.thezdi.com/blog/2019/5/14/the-may-2019-security-update-review>" ], "tools": [ "<https://github.com/rapid7/metasploit-framework/pull/11869>" ]" }
  /// A JSON value containing key/value pairs describing various attributes about this topic.
  pub metadata: MetaData,
  /// The topic score properties.
  pub score: Score,
  pub tags: Vec<TagsOrReferences>,
  pub references: Vec<TagsOrReferences>,
  /// Rapid7's analysis of the topic. This content will be rendered in the UI using Markdown.
  pub rapid7_analysis: Option<String>,
  /// The date and time Rapid7's analysis was created.
  pub rapid7_analysis_created: Option<DateTime<Utc>>,
  /// The date and time Rapid7's analysis was last changed.
  pub rapid7_analysis_revision_date: Option<DateTime<Utc>>,
}
