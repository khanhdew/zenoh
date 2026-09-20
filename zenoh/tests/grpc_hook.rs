// Copyright (c) 2024 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>

#![cfg(feature = "grpc_hook")]

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use tonic::{Request, Response, Status};
use zenoh::config::WhatAmI;
use zenoh::grpc_hook::proto::zenoh_hook_server::{ZenohHook, ZenohHookServer};
use zenoh::grpc_hook::proto::{
    AuthOnPublishRequest, AuthOnPublishResponse, AuthOnRegisterRequest, AuthOnRegisterResponse,
    AuthOnSubscribeRequest, AuthOnSubscribeResponse,
};
use zenoh_config::Config;
use zenoh_core::ztimeout;
use zenoh_test::TestSessions;

const TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Default, Clone)]
struct MockHookService {
    registers: Arc<Mutex<Vec<AuthOnRegisterRequest>>>,
    subscribes: Arc<Mutex<Vec<AuthOnSubscribeRequest>>>,
    publishes: Arc<Mutex<Vec<AuthOnPublishRequest>>>,
    allow_register: Arc<Mutex<bool>>,
    allowed_sub_prefixes: Arc<Mutex<Vec<String>>>,
    allowed_pub_prefixes: Arc<Mutex<Vec<String>>>,
    rewrite_prefix: Arc<Mutex<Option<String>>>,
}

#[tonic::async_trait]
impl ZenohHook for MockHookService {
    async fn auth_on_register(
        &self,
        request: Request<AuthOnRegisterRequest>,
    ) -> Result<Response<AuthOnRegisterResponse>, Status> {
        let req = request.into_inner();
        let allow = *self.allow_register.lock().unwrap();
        self.registers.lock().unwrap().push(req);
        Ok(Response::new(AuthOnRegisterResponse {
            allow,
            reason: if allow { "OK".into() } else { "Registration denied".into() },
        }))
    }

    async fn auth_on_subscribe(
        &self,
        request: Request<AuthOnSubscribeRequest>,
    ) -> Result<Response<AuthOnSubscribeResponse>, Status> {
        let req = request.into_inner();
        let prefixes = self.allowed_sub_prefixes.lock().unwrap().clone();
        let allow = prefixes.iter().any(|prefix| req.key_expr.starts_with(prefix));
        let rewritten_key_expr = self
            .rewrite_prefix
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|p| {
                if !req.key_expr.starts_with(p) {
                    Some(format!("{}/{}", p, req.key_expr))
                } else {
                    None
                }
            });
        self.subscribes.lock().unwrap().push(req);
        Ok(Response::new(AuthOnSubscribeResponse {
            allow,
            reason: if allow { "OK".into() } else { "Subscription denied".into() },
            rewritten_key_expr,
        }))
    }

    async fn auth_on_publish(
        &self,
        request: Request<AuthOnPublishRequest>,
    ) -> Result<Response<AuthOnPublishResponse>, Status> {
        let req = request.into_inner();
        let prefixes = self.allowed_pub_prefixes.lock().unwrap().clone();
        let allow = prefixes.iter().any(|prefix| req.key_expr.starts_with(prefix));
        let rewritten_key_expr = self
            .rewrite_prefix
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|p| {
                if !req.key_expr.starts_with(p) {
                    Some(format!("{}/{}", p, req.key_expr))
                } else {
                    None
                }
            });
        self.publishes.lock().unwrap().push(req);
        Ok(Response::new(AuthOnPublishResponse {
            allow,
            reason: if allow { "OK".into() } else { "Publish denied".into() },
            rewritten_key_expr,
        }))
    }
}

async fn start_mock_grpc_server(
    service: MockHookService,
) -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(ZenohHookServer::new(service))
            .serve_with_shutdown(addr, async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });

    // Wait briefly for server to bind
    tokio::time::sleep(Duration::from_millis(100)).await;
    (addr, shutdown_tx)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_grpc_hook_auth_on_register_allow() {
    let mock = MockHookService::default();
    *mock.allow_register.lock().unwrap() = true;

    let (grpc_addr, shutdown) = start_mock_grpc_server(mock.clone()).await;

    let mut test_context = TestSessions::new();
    let mut router_cfg = Config::default();
    router_cfg.set_mode(Some(WhatAmI::Router)).unwrap();
    router_cfg
        .listen
        .endpoints
        .set(vec!["tcp/127.0.0.1:0".parse().unwrap()])
        .unwrap();
    router_cfg.scouting.multicast.set_enabled(Some(false)).unwrap();
    router_cfg
        .insert_json5(
            "grpc_hook",
            &format!(
                r#"{{
                    enabled: true,
                    endpoint: "http://{}",
                    timeout_ms: 2000,
                    fail_open: false,
                }}"#,
                grpc_addr
            ),
        )
        .unwrap();

    let _router = test_context.open_listener_with_cfg(router_cfg).await;

    let mut client_cfg = test_context.get_connector_config();
    client_cfg.set_mode(Some(WhatAmI::Client)).unwrap();
    let _client_session = test_context.open_connector_with_cfg(client_cfg).await;

    // Wait briefly for the transport hello and hook registration
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Verify auth_on_register was called
    let registers = mock.registers.lock().unwrap();
    assert!(!registers.is_empty(), "auth_on_register must be called on connection");

    test_context.close().await;
    let _ = shutdown.send(());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_grpc_hook_auth_on_register_deny() {
    let mock = MockHookService::default();
    *mock.allow_register.lock().unwrap() = false;

    let (grpc_addr, shutdown) = start_mock_grpc_server(mock.clone()).await;

    let mut test_context = TestSessions::new();
    let mut router_cfg = Config::default();
    router_cfg.set_mode(Some(WhatAmI::Router)).unwrap();
    router_cfg
        .listen
        .endpoints
        .set(vec!["tcp/127.0.0.1:0".parse().unwrap()])
        .unwrap();
    router_cfg.scouting.multicast.set_enabled(Some(false)).unwrap();
    router_cfg
        .insert_json5(
            "grpc_hook",
            &format!(
                r#"{{
                    enabled: true,
                    endpoint: "http://{}",
                    timeout_ms: 2000,
                    fail_open: false,
                }}"#,
                grpc_addr
            ),
        )
        .unwrap();

    let _router = test_context.open_listener_with_cfg(router_cfg).await;

    let mut client_cfg = test_context.get_connector_config();
    client_cfg.set_mode(Some(WhatAmI::Client)).unwrap();
    let client_res = zenoh::open(client_cfg).await;

    // Denied client must fail handshake before OpenAck
    assert!(client_res.is_err(), "Denied client must fail initial handshake");

    // Give time to ensure no reconnect storm
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify auth_on_register was called exactly once (no reconnect loop)
    let registers = mock.registers.lock().unwrap();
    assert_eq!(registers.len(), 1, "auth_on_register must be called once without reconnect spam");
    test_context.close().await;
    let _ = shutdown.send(());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_grpc_hook_auth_on_publish_and_subscribe() {
    let mock = MockHookService::default();
    *mock.allow_register.lock().unwrap() = true;
    mock.allowed_sub_prefixes
        .lock()
        .unwrap()
        .push("test/allowed".to_string());
    mock.allowed_pub_prefixes
        .lock()
        .unwrap()
        .push("test/allowed".to_string());

    let (grpc_addr, shutdown) = start_mock_grpc_server(mock.clone()).await;

    let mut test_context = TestSessions::new();
    let mut router_cfg = Config::default();
    router_cfg.set_mode(Some(WhatAmI::Router)).unwrap();
    router_cfg
        .listen
        .endpoints
        .set(vec!["tcp/127.0.0.1:0".parse().unwrap()])
        .unwrap();
    router_cfg.scouting.multicast.set_enabled(Some(false)).unwrap();
    router_cfg
        .insert_json5(
            "grpc_hook",
            &format!(
                r#"{{
                    enabled: true,
                    endpoint: "http://{}",
                    timeout_ms: 2000,
                    fail_open: false,
                }}"#,
                grpc_addr
            ),
        )
        .unwrap();

    let _router = test_context.open_listener_with_cfg(router_cfg).await;

    let mut client1_cfg = test_context.get_connector_config();
    client1_cfg.set_mode(Some(WhatAmI::Client)).unwrap();
    let sub_session = test_context.open_connector_with_cfg(client1_cfg).await;

    let mut client2_cfg = test_context.get_connector_config();
    client2_cfg.set_mode(Some(WhatAmI::Client)).unwrap();
    let pub_session = test_context.open_connector_with_cfg(client2_cfg).await;

    let subscriber = sub_session
        .declare_subscriber("test/allowed/msg")
        .await
        .expect("declare subscriber failed");

    tokio::time::sleep(Duration::from_millis(500)).await;

    pub_session
        .put("test/allowed/msg", "hello allowed")
        .await
        .expect("put failed");

    let received = ztimeout!(subscriber.recv_async());
    assert!(received.is_ok(), "Allowed subscriber should receive allowed published message");

    {
        let subscribes = mock.subscribes.lock().unwrap();
        let sub = subscribes
            .iter()
            .find(|s| s.key_expr == "test/allowed/msg")
            .expect("auth_on_subscribe must be called for test/allowed/msg");
        assert_eq!(sub.reliability, "reliable");
        assert!(!sub.history);
    }
    {
        let publishes = mock.publishes.lock().unwrap();
        let pub_req = publishes
            .iter()
            .find(|p| p.key_expr == "test/allowed/msg" && p.action == "put")
            .expect("auth_on_publish must be called for test/allowed/msg");
        assert_eq!(pub_req.priority, "data");
        assert_eq!(pub_req.congestion_control, "drop");
    }

    pub_session
        .put("test/denied/msg", "hello denied")
        .await
        .expect("put message sends from client");

    tokio::time::sleep(Duration::from_millis(200)).await;

    {
        let publishes = mock.publishes.lock().unwrap();
        assert!(
            publishes.iter().any(|p| p.key_expr == "test/denied/msg"),
            "auth_on_publish must be called for test/denied/msg"
        );
    }

    subscriber.undeclare().await.unwrap();
    test_context.close().await;
    let _ = shutdown.send(());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_grpc_hook_auth_on_register_usrpwd_credentials() {
    let mock = MockHookService::default();
    *mock.allow_register.lock().unwrap() = true;

    let (grpc_addr, shutdown) = start_mock_grpc_server(mock.clone()).await;

    let mut test_context = TestSessions::new();
    let mut router_cfg = Config::default();
    router_cfg.set_mode(Some(WhatAmI::Router)).unwrap();
    router_cfg
        .listen
        .endpoints
        .set(vec!["tcp/127.0.0.1:0".parse().unwrap()])
        .unwrap();
    router_cfg.scouting.multicast.set_enabled(Some(false)).unwrap();
    router_cfg
        .insert_json5(
            "grpc_hook",
            &format!(
                r#"{{
                    enabled: true,
                    endpoint: "http://{}",
                    timeout_ms: 2000,
                    fail_open: false,
                }}"#,
                grpc_addr
            ),
        )
        .unwrap();

    let _router = test_context.open_listener_with_cfg(router_cfg).await;

    let mut client_cfg = test_context.get_connector_config();
    client_cfg.set_mode(Some(WhatAmI::Client)).unwrap();
    client_cfg
        .transport
        .auth
        .usrpwd
        .set_user(Some("alice".to_owned()))
        .unwrap();
    client_cfg
        .transport
        .auth
        .usrpwd
        .set_password(Some("secret".to_owned()))
        .unwrap();

    let _client_session = test_context.open_connector_with_cfg(client_cfg).await;

    tokio::time::sleep(Duration::from_millis(300)).await;

    let registers = mock.registers.lock().unwrap();
    assert!(!registers.is_empty(), "auth_on_register must be called");
    let reg = registers.iter().find(|r| r.username == "alice");
    assert!(reg.is_some(), "auth_on_register must receive username 'alice'");
    let reg = reg.unwrap();
    assert!(!reg.hmac.is_empty(), "auth_on_register must receive non-empty HMAC");
    assert_ne!(reg.nonce, 0, "auth_on_register must receive non-zero nonce");

    test_context.close().await;
    let _ = shutdown.send(());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_grpc_hook_rewrite_key_expr() {
    let mock = MockHookService::default();
    *mock.allow_register.lock().unwrap() = true;
    *mock.rewrite_prefix.lock().unwrap() = Some("tenant_42".to_owned());
    mock.allowed_sub_prefixes
        .lock()
        .unwrap()
        .push("tenant_42/".to_owned());
    mock.allowed_pub_prefixes
        .lock()
        .unwrap()
        .push("raw/".to_owned());

    let (grpc_addr, shutdown) = start_mock_grpc_server(mock.clone()).await;

    let mut test_context = TestSessions::new();
    let mut router_cfg = Config::default();
    router_cfg.set_mode(Some(WhatAmI::Router)).unwrap();
    router_cfg
        .listen
        .endpoints
        .set(vec!["tcp/127.0.0.1:0".parse().unwrap()])
        .unwrap();
    router_cfg.scouting.multicast.set_enabled(Some(false)).unwrap();
    router_cfg
        .insert_json5(
            "grpc_hook",
            &format!(
                r#"{{
                    enabled: true,
                    endpoint: "http://{}",
                    timeout_ms: 2000,
                    fail_open: false,
                }}"#,
                grpc_addr
            ),
        )
        .unwrap();

    let _router = test_context.open_listener_with_cfg(router_cfg).await;

    let mut client1_cfg = test_context.get_connector_config();
    client1_cfg.set_mode(Some(WhatAmI::Client)).unwrap();
    let sub_session = test_context.open_connector_with_cfg(client1_cfg).await;

    let mut client2_cfg = test_context.get_connector_config();
    client2_cfg.set_mode(Some(WhatAmI::Client)).unwrap();
    let pub_session = test_context.open_connector_with_cfg(client2_cfg).await;

    // Client 1 (backend/collector) subscribes to "tenant_42/raw/data"
    let subscriber = sub_session
        .declare_subscriber("tenant_42/raw/data")
        .await
        .expect("declare subscriber failed");

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Client 2 (device) puts on "raw/data". Hook rewrites to "tenant_42/raw/data"
    pub_session
        .put("raw/data", "hello tenant")
        .await
        .expect("put failed");

    // Client 1 should receive the sample because both were rewritten to "tenant_42/raw/data"
    let received = ztimeout!(subscriber.recv_async());
    assert!(received.is_ok(), "Subscriber should receive message on rewritten topic");
    let sample = received.unwrap();
    assert_eq!(sample.payload().try_to_string().unwrap(), "hello tenant");

    subscriber.undeclare().await.unwrap();
    test_context.close().await;
    let _ = shutdown.send(());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_grpc_hook_max_payload_bytes() {
    let mock = MockHookService::default();
    *mock.allow_register.lock().unwrap() = true;
    mock.allowed_pub_prefixes
        .lock()
        .unwrap()
        .push("test/payload".to_owned());

    let (grpc_addr, shutdown) = start_mock_grpc_server(mock.clone()).await;

    let mut test_context = TestSessions::new();
    let mut router_cfg = Config::default();
    router_cfg.set_mode(Some(WhatAmI::Router)).unwrap();
    router_cfg
        .listen
        .endpoints
        .set(vec!["tcp/127.0.0.1:0".parse().unwrap()])
        .unwrap();
    router_cfg.scouting.multicast.set_enabled(Some(false)).unwrap();
    router_cfg
        .insert_json5(
            "grpc_hook",
            &format!(
                r#"{{
                    enabled: true,
                    endpoint: "http://{}",
                    timeout_ms: 2000,
                    fail_open: false,
                    max_payload_bytes: 10,
                }}"#,
                grpc_addr
            ),
        )
        .unwrap();

    let _router = test_context.open_listener_with_cfg(router_cfg).await;

    let mut client_cfg = test_context.get_connector_config();
    client_cfg.set_mode(Some(WhatAmI::Client)).unwrap();
    let pub_session = test_context.open_connector_with_cfg(client_cfg).await;

    // Send a 16-byte payload; should be truncated to 10 bytes
    pub_session
        .put("test/payload/truncated", "0123456789abcdef")
        .await
        .expect("put failed");

    tokio::time::sleep(Duration::from_millis(500)).await;

    {
        let publishes = mock.publishes.lock().unwrap();
        let pub_req = publishes
            .iter()
            .find(|p| p.key_expr == "test/payload/truncated")
            .expect("auth_on_publish must be called for test/payload/truncated");
        assert_eq!(pub_req.payload, b"0123456789".to_vec());
    }

    test_context.close().await;
    let _ = shutdown.send(());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_grpc_hook_max_payload_bytes_zero() {
    let mock = MockHookService::default();
    *mock.allow_register.lock().unwrap() = true;
    mock.allowed_pub_prefixes
        .lock()
        .unwrap()
        .push("test/payload".to_owned());

    let (grpc_addr, shutdown) = start_mock_grpc_server(mock.clone()).await;

    let mut test_context = TestSessions::new();
    let mut router_cfg = Config::default();
    router_cfg.set_mode(Some(WhatAmI::Router)).unwrap();
    router_cfg
        .listen
        .endpoints
        .set(vec!["tcp/127.0.0.1:0".parse().unwrap()])
        .unwrap();
    router_cfg.scouting.multicast.set_enabled(Some(false)).unwrap();
    router_cfg
        .insert_json5(
            "grpc_hook",
            &format!(
                r#"{{
                    enabled: true,
                    endpoint: "http://{}",
                    timeout_ms: 2000,
                    fail_open: false,
                    max_payload_bytes: 0,
                }}"#,
                grpc_addr
            ),
        )
        .unwrap();

    let _router = test_context.open_listener_with_cfg(router_cfg).await;

    let mut client_cfg = test_context.get_connector_config();
    client_cfg.set_mode(Some(WhatAmI::Client)).unwrap();
    let pub_session = test_context.open_connector_with_cfg(client_cfg).await;

    // Send a payload; with max_payload_bytes: 0, payload should be empty
    pub_session
        .put("test/payload/zero", "some payload data")
        .await
        .expect("put failed");

    tokio::time::sleep(Duration::from_millis(500)).await;

    {
        let publishes = mock.publishes.lock().unwrap();
        let pub_req = publishes
            .iter()
            .find(|p| p.key_expr == "test/payload/zero")
            .expect("auth_on_publish must be called for test/payload/zero");
        assert!(pub_req.payload.is_empty(), "payload must be empty when max_payload_bytes is 0");
    }

    test_context.close().await;
    let _ = shutdown.send(());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_grpc_hook_egress_reverse_rewrite_on_subscribe() {
    let mock = MockHookService::default();
    *mock.allow_register.lock().unwrap() = true;
    *mock.rewrite_prefix.lock().unwrap() = Some("tenant_42".to_owned());
    mock.allowed_sub_prefixes
        .lock()
        .unwrap()
        .push("provision/".to_owned());
    mock.allowed_pub_prefixes
        .lock()
        .unwrap()
        .push("tenant_42/".to_owned());

    let (grpc_addr, shutdown) = start_mock_grpc_server(mock.clone()).await;

    let mut test_context = TestSessions::new();
    let mut router_cfg = Config::default();
    router_cfg.set_mode(Some(WhatAmI::Router)).unwrap();
    router_cfg
        .listen
        .endpoints
        .set(vec!["tcp/127.0.0.1:0".parse().unwrap()])
        .unwrap();
    router_cfg.scouting.multicast.set_enabled(Some(false)).unwrap();
    router_cfg
        .insert_json5(
            "grpc_hook",
            &format!(
                r#"{{
                    enabled: true,
                    endpoint: "http://{}",
                    timeout_ms: 2000,
                    fail_open: false,
                }}"#,
                grpc_addr
            ),
        )
        .unwrap();

    let _router = test_context.open_listener_with_cfg(router_cfg).await;

    let mut client1_cfg = test_context.get_connector_config();
    client1_cfg.set_mode(Some(WhatAmI::Client)).unwrap();
    let dev_session = test_context.open_connector_with_cfg(client1_cfg).await;

    let mut client2_cfg = test_context.get_connector_config();
    client2_cfg.set_mode(Some(WhatAmI::Client)).unwrap();
    let backend_session = test_context.open_connector_with_cfg(client2_cfg).await;

    // Device subscribes to clean "provision/response"
    // The gRPC hook rewrites the subscriber's wire_expr on ingress to "tenant_42/provision/response"
    let subscriber = dev_session
        .declare_subscriber("provision/response")
        .await
        .expect("device declare subscriber failed");

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Backend publishes to the sandboxed topic "tenant_42/provision/response"
    backend_session
        .put("tenant_42/provision/response", "creds_for_dev")
        .await
        .expect("backend put failed");

    // The device subscriber declared "provision/response".
    // With Egress Interceptor, the router rewrites the outgoing wire key back to "provision/response".
    // Without Egress Interceptor, this will fail/timeout because wire expr is "tenant_42/provision/response".
    let received = ztimeout!(subscriber.recv_async());
    assert!(
        received.is_ok(),
        "Device subscriber must receive the message on its declared topic 'provision/response'"
    );
    let sample = received.unwrap();
    assert_eq!(sample.key_expr().as_str(), "provision/response");
    assert_eq!(sample.payload().try_to_string().unwrap(), "creds_for_dev");

    subscriber.undeclare().await.unwrap();
    test_context.close().await;
    let _ = shutdown.send(());
}



