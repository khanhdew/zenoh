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

//! ⚠️ WARNING ⚠️
//!
//! This module is intended for Zenoh's internal use.
//!
//! gRPC Auth Hook Interceptor
//! ==========================
//!
//! Mirrors MQTT broker-style auth hooks (VerneMQ / MQTT) for Zenoh:
//!
//! - `auth_on_register` — called when a new transport connects
//! - `auth_on_subscribe` — called for DeclareSubscriber / DeclareQueryable
//! - `auth_on_publish`  — called for Put / Delete / Query / Reply

use std::{any::Any, sync::{Arc, RwLock}, time::Duration};

use zenoh_config::GrpcHookConfig;
use zenoh_keyexpr::keyexpr;
use zenoh_protocol::{
    core::{WireExpr, ZenohIdProto},
    network::{
        Declare, DeclareBody, Mapping, NetworkBodyMut, NetworkMessageMut,
        Push, Request, Response,
    },
    zenoh::{PushBody, RequestBody},
};
use zenoh_result::ZResult;
use zenoh_transport::{multicast::TransportMulticast, unicast::TransportUnicast};

use super::{EgressInterceptor, IngressInterceptor, InterceptorContext, InterceptorFactory,
    InterceptorFactoryTrait, InterceptorTrait};

// Include the prost-generated gRPC client code.
pub mod proto {
    tonic::include_proto!("zenoh_hook");
}
use proto::zenoh_hook_client::ZenohHookClient;
use proto::{
    AuthOnPublishRequest, AuthOnRegisterRequest, AuthOnSubscribeRequest,
};

// ─── shared gRPC channel ─────────────────────────────────────────────────────

/// Shared, cheaply-cloneable gRPC connection to the hook server.
#[derive(Clone)]
struct HookClient {
    client: ZenohHookClient<tonic::transport::Channel>,
    timeout: Duration,
    fail_open: bool,
    max_payload_bytes: usize,
}

impl HookClient {
    /// Blocking bridge: runs an async gRPC future on the current tokio runtime
    /// while yielding the thread to the scheduler so other tasks can make progress.
    ///
    /// On `MultiThread` runtimes, `tokio::task::block_in_place` is used so other tasks
    /// can continue executing on worker threads while `Handle::block_on` drives the future.
    /// On `CurrentThread` runtimes where `block_in_place` panics, a scoped OS thread is spawned
    /// to run the blocking wait off the runtime thread.
    ///
    /// This ensures the hook is a hard gate — the message is not forwarded until
    /// the gRPC server replies (or the timeout fires).
    fn call_hook<F, R>(&self, fut: F) -> Result<R, ()>
    where
        F: std::future::Future<Output = Result<tonic::Response<R>, tonic::Status>>
            + Send
            + 'static,
        R: Send + 'static,
    {
        let timeout = self.timeout;
        let handle = tokio::runtime::Handle::current();
        match handle.runtime_flavor() {
            tokio::runtime::RuntimeFlavor::CurrentThread => {
                // block_in_place panics on CurrentThread runtime; execute in a scoped OS thread
                std::thread::scope(|s| {
                    s.spawn(move || {
                        handle.block_on(async move {
                            tokio::time::timeout(timeout, fut).await
                        })
                    })
                    .join()
                    .map_err(|_| ())?
                    .map_err(|_| ())
                })
            }
            _ => {
                tokio::task::block_in_place(|| {
                    handle.block_on(async move {
                        tokio::time::timeout(timeout, fut).await
                    })
                })
                .map_err(|_| ())
            }
        }
        .map_err(|_elapsed| ()) // timeout
        .and_then(|res| res.map_err(|_| ())) // gRPC error
        .map(|resp| resp.into_inner())
    }

    /// `auth_on_register` — gate a new transport connection.
    /// Returns `true` to allow, `false` to deny and drop the connection.
    fn auth_on_register(&self, req: AuthOnRegisterRequest) -> bool {
        let mut client = self.client.clone();
        let fail_open = self.fail_open;
        match self.call_hook(async move { client.auth_on_register(req).await }) {
            Ok(resp) => resp.allow,
            Err(()) => {
                tracing::warn!("grpc_hook auth_on_register failed (fail_open={})", fail_open);
                fail_open
            }
        }
    }

    /// `auth_on_subscribe` — gate DeclareSubscriber / DeclareQueryable messages.
    /// Returns `(allow, rewritten_key_expr)`.
    fn auth_on_subscribe(&self, req: AuthOnSubscribeRequest) -> (bool, Option<String>) {
        let mut client = self.client.clone();
        let fail_open = self.fail_open;
        match self.call_hook(async move { client.auth_on_subscribe(req).await }) {
            Ok(resp) => (resp.allow, resp.rewritten_key_expr),
            Err(()) => {
                tracing::warn!("grpc_hook auth_on_subscribe failed (fail_open={})", fail_open);
                (fail_open, None)
            }
        }
    }

    /// `auth_on_publish` — gate Put / Delete / Query / Reply messages.
    /// Returns `(allow, rewritten_key_expr)`.
    fn auth_on_publish(&self, req: AuthOnPublishRequest) -> (bool, Option<String>) {
        let mut client = self.client.clone();
        let fail_open = self.fail_open;
        match self.call_hook(async move { client.auth_on_publish(req).await }) {
            Ok(resp) => (resp.allow, resp.rewritten_key_expr),
            Err(()) => {
                tracing::warn!("grpc_hook auth_on_publish failed (fail_open={})", fail_open);
                (fail_open, None)
            }
        }
    }
}

// ─── Factory ─────────────────────────────────────────────────────────────────

/// Per-session metadata extracted at transport-open time.
struct PeerMeta {
    peer_id: String,
    username: String,
    cert_cn: String,
    link_protocol: String,
    interface: String,
}

/// The interceptor factory.  One instance is created at startup and shared
/// across all transports.
pub(crate) struct GrpcHookInterceptorFactory {
    hook: Arc<HookClient>,
}

impl InterceptorFactoryTrait for GrpcHookInterceptorFactory {
    fn new_transport_unicast(
        &self,
        transport: &TransportUnicast,
    ) -> ZResult<(Option<IngressInterceptor>, Option<EgressInterceptor>)> {
        // ── Collect peer metadata ─────────────────────────────────────────
        let peer_id = transport
            .get_zid()
            .map(|z| format!("{z:?}"))
            .unwrap_or_default();

        let auth_ids = match transport.get_auth_ids() {
            Ok(ids) => ids,
            Err(e) => {
                tracing::warn!("grpc_hook: could not get auth IDs for {peer_id}: {e}");
                if !self.hook.fail_open {
                    zenoh_result::bail!("grpc_hook: could not get auth IDs for {peer_id}: {e}");
                }
                return Ok((None, None));
            }
        };

        let username = auth_ids.username().cloned().unwrap_or_default();

        let mut cert_cn = String::new();
        let mut link_protocol = String::new();
        for link_auth in auth_ids.link_auth_ids() {
            match link_auth {
                zenoh_link::LinkAuthId::Tls(cn) => {
                    cert_cn = cn.as_deref().unwrap_or("").to_owned();
                    link_protocol = "tls".to_owned();
                }
                zenoh_link::LinkAuthId::Quic(cn) => {
                    cert_cn = cn.as_deref().unwrap_or("").to_owned();
                    link_protocol = "quic".to_owned();
                }
                zenoh_link::LinkAuthId::Tcp => link_protocol = "tcp".to_owned(),
                zenoh_link::LinkAuthId::Udp => link_protocol = "udp".to_owned(),
                zenoh_link::LinkAuthId::Serial => link_protocol = "serial".to_owned(),
                zenoh_link::LinkAuthId::Unixpipe => link_protocol = "unixpipe".to_owned(),
                zenoh_link::LinkAuthId::UnixsockStream => {
                    link_protocol = "unixsock_stream".to_owned()
                }
                zenoh_link::LinkAuthId::Vsock => link_protocol = "vsock".to_owned(),
                zenoh_link::LinkAuthId::Ws => link_protocol = "ws".to_owned(),
            }
        }

        let interface = transport
            .get_links()
            .ok()
            .and_then(|links| links.into_iter().next())
            .and_then(|link| link.interfaces.into_iter().next())
            .unwrap_or_default();

        let hmac = auth_ids.usrpwd_hmac().map(|h| h.to_vec()).unwrap_or_default();
        let nonce = auth_ids.usrpwd_nonce().unwrap_or_default();

        // ── auth_on_register ──────────────────────────────────────────────
        let allowed = self.hook.auth_on_register(AuthOnRegisterRequest {
            peer_id: peer_id.clone(),
            cert_cn: cert_cn.clone(),
            username: username.clone(),
            link_protocol: link_protocol.clone(),
            interface: interface.clone(),
            hmac,
            nonce,
        });

        if !allowed {
            tracing::info!("grpc_hook: auth_on_register DENIED for peer {peer_id}");
            zenoh_result::bail!("grpc_hook: auth_on_register DENIED for peer {peer_id}");
        }
        tracing::debug!("grpc_hook: auth_on_register allowed for peer {peer_id}");

        let meta = Arc::new(PeerMeta {
            peer_id,
            username,
            cert_cn,
            link_protocol,
            interface,
        });

        let reverse_table = Arc::new(RwLock::new(ReverseRewriteTable::default()));

        let ingress = Box::new(GrpcHookInterceptor {
            hook: self.hook.clone(),
            meta,
            zid: transport.get_zid().unwrap_or_default(),
            reverse_table: reverse_table.clone(),
        });
        let egress = Box::new(GrpcHookEgressInterceptor {
            reverse_table,
        });
        Ok((Some(ingress), Some(egress)))
    }

    fn new_transport_multicast(&self, _transport: &TransportMulticast) -> Option<EgressInterceptor> {
        // Multicast is not supported by the gRPC hook.
        None
    }

    fn new_peer_multicast(&self, _transport: &TransportMulticast) -> Option<IngressInterceptor> {
        None
    }
}

// ─── Reverse rewrite mapping for egress ──────────────────────────────────────

#[derive(Default, Debug)]
pub(crate) struct ReverseRewriteTable {
    /// Exact matches: (rewritten, original)
    exact: Vec<(String, String)>,
    /// Prefix matches: (rewritten_prefix, original_prefix)
    prefix: Vec<(String, String)>,
}

impl ReverseRewriteTable {
    pub fn insert(&mut self, rewritten: &str, original: &str) {
        if rewritten == original {
            return;
        }
        let wildcard_pos = original.find(['*', '+', '$']);
        if let Some(pos) = wildcard_pos {
            let orig_prefix = &original[..pos];
            let rew_wildcard_pos = rewritten.find(['*', '+', '$']);
            let rew_prefix = match rew_wildcard_pos {
                Some(r_pos) => &rewritten[..r_pos],
                None => rewritten,
            };
            if !self.prefix.iter().any(|(r, _)| r == rew_prefix) {
                self.prefix.push((rew_prefix.to_owned(), orig_prefix.to_owned()));
            }
        } else if !self.exact.iter().any(|(r, _)| r == rewritten) {
            self.exact.push((rewritten.to_owned(), original.to_owned()));
        }
    }

    pub fn reverse(&self, key: &str) -> Option<String> {
        for (rewritten, original) in &self.exact {
            if key == rewritten {
                return Some(original.clone());
            }
        }
        for (rew_prefix, orig_prefix) in &self.prefix {
            if let Some(suffix) = key.strip_prefix(rew_prefix) {
                return Some(format!("{}{}", orig_prefix, suffix));
            }
        }
        None
    }
}

// ─── Per-message interceptor ─────────────────────────────────────────────────

struct GrpcHookInterceptor {
    hook: Arc<HookClient>,
    meta: Arc<PeerMeta>,
    zid: ZenohIdProto,
    reverse_table: Arc<RwLock<ReverseRewriteTable>>,
}

struct GrpcHookEgressInterceptor {
    reverse_table: Arc<RwLock<ReverseRewriteTable>>,
}

impl InterceptorTrait for GrpcHookEgressInterceptor {
    fn compute_keyexpr_cache(&self, _key_expr: &keyexpr) -> Option<Box<dyn Any + Send + Sync>> {
        None
    }

    fn intercept(&self, msg: &mut NetworkMessageMut, ctx: &mut dyn InterceptorContext) -> bool {
        let key = ctx
            .full_expr(msg)
            .map(|s| s.to_owned())
            .or_else(|| match &msg.body {
                NetworkBodyMut::Push(p) => Some(p.wire_expr.suffix.to_string()),
                NetworkBodyMut::Request(r) => Some(r.wire_expr.suffix.to_string()),
                NetworkBodyMut::Response(r) => Some(r.wire_expr.suffix.to_string()),
                _ => None,
            })
            .unwrap_or_default();

        if key.starts_with('@') || key.is_empty() {
            return true;
        }

        let reversed = if let Ok(table) = self.reverse_table.read() {
            table.reverse(&key)
        } else {
            None
        };

        if let Some(new_key) = reversed {
            tracing::debug!("grpc_hook: egress reverse rewrite: '{}' -> '{}'", key, new_key);
            match &mut msg.body {
                NetworkBodyMut::Push(Push { wire_expr, .. }) => {
                    GrpcHookInterceptor::apply_rewrite(wire_expr, &new_key);
                }
                NetworkBodyMut::Request(Request { wire_expr, .. }) => {
                    GrpcHookInterceptor::apply_rewrite(wire_expr, &new_key);
                }
                NetworkBodyMut::Response(Response { wire_expr, .. }) => {
                    GrpcHookInterceptor::apply_rewrite(wire_expr, &new_key);
                }
                _ => {}
            }
        }

        true
    }
}

fn format_priority(p: zenoh_protocol::core::Priority) -> &'static str {
    match p {
        zenoh_protocol::core::Priority::Control => "control",
        zenoh_protocol::core::Priority::RealTime => "real_time",
        zenoh_protocol::core::Priority::InteractiveHigh => "interactive_high",
        zenoh_protocol::core::Priority::InteractiveLow => "interactive_low",
        zenoh_protocol::core::Priority::DataHigh => "data_high",
        zenoh_protocol::core::Priority::Data => "data",
        zenoh_protocol::core::Priority::DataLow => "data_low",
        zenoh_protocol::core::Priority::Background => "background",
    }
}

fn format_congestion_control(c: zenoh_protocol::core::CongestionControl) -> &'static str {
    match c {
        zenoh_protocol::core::CongestionControl::Block => "block",
        zenoh_protocol::core::CongestionControl::Drop => "drop",
        #[cfg(feature = "unstable")]
        zenoh_protocol::core::CongestionControl::BlockFirst => "block_first",
    }
}

fn format_query_target(t: zenoh_protocol::network::request::ext::QueryTarget) -> &'static str {
    match t {
        zenoh_protocol::network::request::ext::QueryTarget::BestMatching => "best_matching",
        zenoh_protocol::network::request::ext::QueryTarget::All => "all",
        zenoh_protocol::network::request::ext::QueryTarget::AllComplete => "all_complete",
    }
}

impl GrpcHookInterceptor {
    /// Build a subscribe request for the given key expression and kind label.
    fn subscribe_req(
        &self,
        key_expr: &str,
        kind: &str,
        reliability: &str,
        history: bool,
    ) -> AuthOnSubscribeRequest {
        AuthOnSubscribeRequest {
            peer_id: self.meta.peer_id.clone(),
            username: self.meta.username.clone(),
            key_expr: key_expr.to_owned(),
            kind: kind.to_owned(),
            cert_cn: self.meta.cert_cn.clone(),
            link_protocol: self.meta.link_protocol.clone(),
            interface: self.meta.interface.clone(),
            reliability: reliability.to_owned(),
            history,
        }
    }

    /// Build a publish request for the given key expression, action label, and payload.
    fn publish_req(
        &self,
        key_expr: &str,
        action: &str,
        payload: Vec<u8>,
        congestion_control: &str,
        priority: &str,
        query_parameters: &str,
        query_target: &str,
    ) -> AuthOnPublishRequest {
        AuthOnPublishRequest {
            peer_id: self.meta.peer_id.clone(),
            username: self.meta.username.clone(),
            key_expr: key_expr.to_owned(),
            action: action.to_owned(),
            cert_cn: self.meta.cert_cn.clone(),
            link_protocol: self.meta.link_protocol.clone(),
            interface: self.meta.interface.clone(),
            payload,
            congestion_control: congestion_control.to_owned(),
            priority: priority.to_owned(),
            query_parameters: query_parameters.to_owned(),
            query_target: query_target.to_owned(),
        }
    }

    /// Helper to rewrite wire_expr with a new key expression.
    fn apply_rewrite(wire_expr: &mut WireExpr<'static>, new_key: &str) {
        let trimmed = new_key.trim();
        if !trimmed.is_empty() {
            if let Ok(valid_ke) = keyexpr::new(trimmed) {
                tracing::debug!("grpc_hook: rewriting keyexpr '{}' -> '{}'", wire_expr, valid_ke);
                wire_expr.scope = 0;
                wire_expr.suffix = std::borrow::Cow::Owned(valid_ke.as_str().to_owned());
                wire_expr.mapping = Mapping::Sender;
            } else {
                tracing::warn!("grpc_hook: invalid rewritten keyexpr '{}', ignoring rewrite", trimmed);
            }
        }
    }
}

impl InterceptorTrait for GrpcHookInterceptor {
    fn compute_keyexpr_cache(&self, _key_expr: &keyexpr) -> Option<Box<dyn Any + Send + Sync>> {
        // No pre-computed cache — we call the gRPC server on each message.
        None
    }

    fn intercept(&self, msg: &mut NetworkMessageMut, ctx: &mut dyn InterceptorContext) -> bool {
        let key = ctx.full_expr(msg).unwrap_or("").to_owned();
        if key.starts_with('@') {
            return true;
        }

        let allowed = match &mut msg.body {
            // ── Publish (Put) ───────────────────────────────────────────
            NetworkBodyMut::Push(Push {
                payload: PushBody::Put(put),
                wire_expr,
                ext_qos,
                ..
            }) => {
                let payload = if self.hook.max_payload_bytes == 0 {
                    Vec::new()
                } else {
                    let zslice = put.payload.to_zslice();
                    let len = zslice.len().min(self.hook.max_payload_bytes);
                    zslice[..len].to_vec()
                };
                let prio = format_priority(ext_qos.get_priority());
                let cctrl = format_congestion_control(ext_qos.get_congestion_control());
                let (allow, rewritten) = self.hook.auth_on_publish(self.publish_req(
                    &key, "put", payload, cctrl, prio, "", "",
                ));
                if allow {
                    if let Some(new_key) = rewritten {
                        Self::apply_rewrite(wire_expr, &new_key);
                    }
                    true
                } else {
                    false
                }
            }
            // ── Publish (Del) ───────────────────────────────────────────
            NetworkBodyMut::Push(Push {
                payload: PushBody::Del(_),
                wire_expr,
                ext_qos,
                ..
            }) => {
                let prio = format_priority(ext_qos.get_priority());
                let cctrl = format_congestion_control(ext_qos.get_congestion_control());
                let (allow, rewritten) = self.hook.auth_on_publish(self.publish_req(
                    &key, "delete", Vec::new(), cctrl, prio, "", "",
                ));
                if allow {
                    if let Some(new_key) = rewritten {
                        Self::apply_rewrite(wire_expr, &new_key);
                    }
                    true
                } else {
                    false
                }
            }
            // ── Request (Query) ─────────────────────────────────────────
            NetworkBodyMut::Request(Request {
                payload: RequestBody::Query(query),
                wire_expr,
                ext_qos,
                ext_target,
                ..
            }) => {
                let prio = format_priority(ext_qos.get_priority());
                let cctrl = format_congestion_control(ext_qos.get_congestion_control());
                let target = format_query_target(*ext_target);
                let (allow, rewritten) = self.hook.auth_on_publish(self.publish_req(
                    &key, "query", Vec::new(), cctrl, prio, &query.parameters, target,
                ));
                if allow {
                    if let Some(new_key) = rewritten {
                        Self::apply_rewrite(wire_expr, &new_key);
                    }
                    true
                } else {
                    false
                }
            }
            // ── Response (Reply) ────────────────────────────────────────
            NetworkBodyMut::Response(Response {
                wire_expr,
                ext_qos,
                ..
            }) => {
                let prio = format_priority(ext_qos.get_priority());
                let cctrl = format_congestion_control(ext_qos.get_congestion_control());
                let (allow, rewritten) = self.hook.auth_on_publish(self.publish_req(
                    &key, "reply", Vec::new(), cctrl, prio, "", "",
                ));
                if allow {
                    if let Some(new_key) = rewritten {
                        Self::apply_rewrite(wire_expr, &new_key);
                    }
                    true
                } else {
                    false
                }
            }
            // ── Subscribe / Queryable ───────────────────────────────────
            NetworkBodyMut::Declare(Declare { body, .. }) => match body {
                DeclareBody::DeclareSubscriber(sub) => {
                    let (allow, rewritten) = self.hook.auth_on_subscribe(
                        self.subscribe_req(&key, "subscriber", "reliable", false),
                    );
                    if allow {
                        if let Some(new_key) = rewritten {
                            Self::apply_rewrite(&mut sub.wire_expr, &new_key);
                            if let Ok(mut table) = self.reverse_table.write() {
                                table.insert(&new_key, &key);
                            }
                        }
                        true
                    } else {
                        false
                    }
                }
                DeclareBody::DeclareQueryable(q) => {
                    let (allow, rewritten) = self.hook.auth_on_subscribe(
                        self.subscribe_req(&key, "queryable", "reliable", q.ext_info.complete),
                    );
                    if allow {
                        if let Some(new_key) = rewritten {
                            Self::apply_rewrite(&mut q.wire_expr, &new_key);
                            if let Ok(mut table) = self.reverse_table.write() {
                                table.insert(&new_key, &key);
                            }
                        }
                        true
                    } else {
                        false
                    }
                }
                _ => true,
            },
            _ => true,
        };

        if !allowed {
            tracing::debug!(
                "grpc_hook: message DENIED for peer {} (zid {:?})",
                self.meta.peer_id,
                self.zid,
            );
        }
        allowed
    }
}

// ─── Factory constructor ──────────────────────────────────────────────────────

/// Build the gRPC hook interceptor factories from config.
pub(crate) fn grpc_hook_interceptor_factories(
    cfg: &GrpcHookConfig,
) -> ZResult<Vec<InterceptorFactory>> {
    if !cfg.enabled {
        return Ok(vec![]);
    }

    let endpoint = cfg.endpoint.clone();
    if endpoint.is_empty() {
        zenoh_result::bail!("grpc_hook is enabled but `endpoint` is not configured");
    }

    // Connect lazily (tonic's channel is lazy by default).
    let channel = tonic::transport::Channel::from_shared(endpoint.clone())
        .map_err(|e| zenoh_result::zerror!("grpc_hook: invalid endpoint '{}': {}", endpoint, e))?
        .connect_lazy();

    let client = ZenohHookClient::new(channel);
    let hook = Arc::new(HookClient {
        client,
        timeout: Duration::from_millis(cfg.timeout_ms),
        fail_open: cfg.fail_open,
        max_payload_bytes: cfg.max_payload_bytes,
    });

    tracing::info!(
        "grpc_hook: enabled, endpoint={}, timeout={}ms, fail_open={}, max_payload_bytes={}",
        endpoint,
        cfg.timeout_ms,
        cfg.fail_open,
        cfg.max_payload_bytes
    );

    Ok(vec![Box::new(GrpcHookInterceptorFactory { hook })])
}
