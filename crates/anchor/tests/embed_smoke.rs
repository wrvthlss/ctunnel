use std::collections::HashSet;

use anchor::{connect, listen, Identity, TrustPolicy};

#[tokio::test]
async fn embed_api_smoke_test() {
    let server_id = Identity::generate().await.unwrap();
    let client_id = Identity::generate().await.unwrap();
    let client_pk = client_id.public_key;

    let mut allow = HashSet::new();
    allow.insert(client_pk);

    let server = listen(
        "127.0.0.1:0",
        server_id.clone(),
        TrustPolicy::AllowList(allow),
    )
    .await
    .unwrap();

    let addr = server.local_addr().unwrap().to_string();

    let server_pk = server_id.public_key;

    let server_task = tokio::spawn(async move {
        let mut conn = server.accept().await.unwrap();
        let msg = conn.recv().await.unwrap();
        conn.send(&msg).await.unwrap();
        conn.peer_identity()
    });

    let mut client = connect(
        &addr,
        client_id,
        TrustPolicy::Pinned(server_pk),
    )
    .await
    .unwrap();

    client.send(b"anchor-embed-test").await.unwrap();
    let echo = client.recv().await.unwrap();
    assert_eq!(echo, b"anchor-embed-test");

    let peer_seen = server_task.await.unwrap();
    assert_eq!(peer_seen, client_pk);
}