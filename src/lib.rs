//! A guide to the public REST API for AttackerKB. To generate an API key, navigate to the API tab on your AttackerKB Profile Page.
//!  For more details on the API referer to <https://extensions.rapid7.com/extension/rapid7-attackerkb>
use crate::error::{Error, ErrorResponse, StatusCode};
use crate::pagination::KBResponse;
use crate::v1::query::{AssessmentsParameters, ContributorsParameters, TopicsParameters};
use reqwest::{header, ClientBuilder, RequestBuilder};
use std::fmt::Display;

pub mod error;
pub mod pagination;
pub mod v1;

const BASE_URL: &str = "https://api.attackerkb.com";

/// API client, API token needs to be provided when creating a new instance.
#[derive(Debug, Clone)]
pub struct AttackKBApi {
  base_path: String,
  version: ApiVersion,
  client: reqwest::Client,
}

/// ApiVersion default: v1
#[derive(Debug, Clone)]
pub enum ApiVersion {
  V1,
}

impl Default for ApiVersion {
  fn default() -> Self {
    Self::V1
  }
}

impl Display for ApiVersion {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      f,
      "{}",
      match self {
        ApiVersion::V1 => String::from("v1"),
      }
    )
  }
}

impl AttackKBApi {
  pub fn new(api_token: Option<impl Into<String>>) -> Result<Self, Error> {
    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(api_token) = api_token {
      let mut auth_value =
        reqwest::header::HeaderValue::from_str(&format!("basic {}", api_token.into()))
          .map_err(|source| Error::InvalidApiToken { source })?;
      auth_value.set_sensitive(true);
      headers.insert(
        header::ACCEPT,
        header::HeaderValue::from_static("application/json"),
      );
      headers.insert(header::AUTHORIZATION, auth_value);
    }
    let api_client = ClientBuilder::new()
      .default_headers(headers)
      .build()
      .map_err(|source| Error::BuildingClient { source })?;
    Ok(AttackKBApi {
      base_path: BASE_URL.to_owned(),
      version: ApiVersion::default(),
      client: api_client,
    })
  }
}

impl AttackKBApi {
  async fn request(&self, request: RequestBuilder) -> Result<KBResponse, Error> {
    let request = request.build()?;
    let resp = self
      .client
      .execute(request)
      .await
      .map_err(|source| Error::RequestFailed { source })?;
    if !resp.status().is_success() {
      return Err(Error::Api {
        error: ErrorResponse {
          message: "not success request".to_string(),
          status: StatusCode::NonZeroU16(resp.status().as_u16()),
        },
      });
    };
    let result = resp
      .json()
      .await
      .map_err(|source| Error::ResponseIo { source })?;
    // let result = serde_json::from_str(&json).unwrap();
    if let KBResponse::Error(err) = &result {
      return Err(Error::Api { error: err.clone() });
    }
    Ok(result)
  }
}

impl AttackKBApi {
  /// Return all topics.
  pub async fn topics(&self, query: &TopicsParameters) -> Result<KBResponse, Error> {
    let u = format!("{}/{}/{}", self.base_path, self.version, "topics");
    self.request(self.client.get(u).query(&query)).await
  }
  /// Return a specific topic.
  pub async fn topic(&self, id: impl Into<String>) -> Result<KBResponse, Error> {
    let u = format!(
      "{}/{}/{}/{}",
      self.base_path,
      self.version,
      "topics",
      id.into()
    );
    self.request(self.client.get(u)).await
  }
  /// Return all assessments.
  pub async fn assessments(&self, query: &AssessmentsParameters) -> Result<KBResponse, Error> {
    let u = format!("{}/{}/{}", self.base_path, self.version, "assessments");
    self.request(self.client.get(u).query(&query)).await
  }
  /// Return a specific assessment.
  pub async fn assessment(&self, id: impl Into<String>) -> Result<KBResponse, Error> {
    let u = format!(
      "{}/{}/{}/{}",
      self.base_path,
      self.version,
      "assessments",
      id.into()
    );
    self.request(self.client.get(u)).await
  }
  /// Return all contributors.
  pub async fn contributors(&self, query: &ContributorsParameters) -> Result<KBResponse, Error> {
    let u = format!("{}/{}/{}", self.base_path, self.version, "contributors");
    self.request(self.client.get(u).query(&query)).await
  }
  /// Return a specific contributor.
  pub async fn contributor(&self, id: impl Into<String>) -> Result<KBResponse, Error> {
    let u = format!(
      "{}/{}/{}/{}",
      self.base_path,
      self.version,
      "contributors",
      id.into()
    );
    self.request(self.client.get(u)).await
  }
}

#[cfg(test)]
mod tests {
  #[test]
  fn it_works() {
    let result = 2 + 2;
    assert_eq!(result, 4);
  }
}
