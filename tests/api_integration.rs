use cybersec_ai_agent_backend::api::api_routes;
use warp::test;

#[tokio::test]
async fn test_health_check() {
    let api = api_routes();
    let response = test::request()
        .path("/health")
        .reply(&api)
        .await;

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), "\"API is running\"");
}
