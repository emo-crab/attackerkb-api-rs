use attackerkb_api_rs::v1::query::TopicsParametersBuilder;
use attackerkb_api_rs::AttackKBApi;

#[tokio::main]
async fn main() {
  let token =
    Some("see your profile like: https://attackerkb.com/contributors/cn-kali-team#api".to_string());
  let api = AttackKBApi::new(token).unwrap();
  let query = TopicsParametersBuilder::default()
    .size(10)
    .q(Some("cve-2023-46805".into()))
    .build()
    .unwrap();
  let list_resp = api.topics(&query).await.unwrap();
  println!("{:#?}", list_resp);
  let single_resp = api
    .topic("40a59992-3535-439c-a358-ec629cfa6115")
    .await
    .unwrap();
  println!("{:#?}", single_resp);
}
