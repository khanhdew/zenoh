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

use std::net::SocketAddr;
use tonic::{Request, Response, Status};
use zenoh::grpc_hook::proto::zenoh_hook_server::{ZenohHook, ZenohHookServer};
use zenoh::grpc_hook::proto::{
    AuthOnPublishRequest, AuthOnPublishResponse, AuthOnRegisterRequest, AuthOnRegisterResponse,
    AuthOnSubscribeRequest, AuthOnSubscribeResponse,
};

#[derive(Default)]
struct ExampleHookService;

#[tonic::async_trait]
impl ZenohHook for ExampleHookService {
    async fn auth_on_register(
        &self,
        request: Request<AuthOnRegisterRequest>,
    ) -> Result<Response<AuthOnRegisterResponse>, Status> {
        let req = request.into_inner();
        let hmac_info = if !req.hmac.is_empty() {
            format!(", hmac_len={}, nonce={}", req.hmac.len(), req.nonce)
        } else {
            String::new()
        };
        println!(
            "\x1b[36m[AUTH ON REGISTER]\x1b[0m peer_id='{}', username='{}', cert_cn='{}', link='{}', iface='{}'{}",
            req.peer_id, req.username, req.cert_cn, req.link_protocol, req.interface, hmac_info
        );
        // By default, allow all incoming registrations (or deny if username == "blocked")
        let allow = req.username != "blocked";
        println!(
            "  └─> \x1b[1mDecision:\x1b[0m {}",
            if allow { "\x1b[32mALLOW\x1b[0m" } else { "\x1b[31mDENY\x1b[0m" }
        );
        Ok(Response::new(AuthOnRegisterResponse {
            allow,
            reason: if allow { "OK".into() } else { "Registration blocked by hook".into() },
        }))
    }

    async fn auth_on_subscribe(
        &self,
        request: Request<AuthOnSubscribeRequest>,
    ) -> Result<Response<AuthOnSubscribeResponse>, Status> {
        let req = request.into_inner();
        println!(
            "\x1b[33m[AUTH ON SUBSCRIBE]\x1b[0m peer_id='{}', key_expr='{}', kind='{}'",
            req.peer_id, req.key_expr, req.kind
        );
        // Deny any key containing "deny" or "forbidden"
        let allow = !req.key_expr.contains("deny") && !req.key_expr.contains("forbidden");
        let rewritten_key_expr = if allow && !req.key_expr.starts_with(&req.peer_id) {
            let new_key = format!("{}/{}", req.peer_id, req.key_expr);
            println!("  └─> \x1b[36mRewrite:\x1b[0m '{}' -> '{}'", req.key_expr, new_key);
            Some(new_key)
        } else {
            None
        };
        println!(
            "  └─> \x1b[1mDecision:\x1b[0m {}",
            if allow { "\x1b[32mALLOW\x1b[0m" } else { "\x1b[31mDENY\x1b[0m" }
        );
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
        let payload_preview = String::from_utf8_lossy(&req.payload);
        println!(
            "\x1b[35m[AUTH ON PUBLISH]\x1b[0m peer_id='{}', key_expr='{}', action='{}', payload='{}'",
            req.peer_id, req.key_expr, req.action, payload_preview
        );
        // Deny any key containing "deny" or "forbidden"
        let allow = !req.key_expr.contains("deny") && !req.key_expr.contains("forbidden");
        let rewritten_key_expr = if allow && !req.key_expr.starts_with(&req.peer_id) {
            let new_key = format!("{}/{}", req.peer_id, req.key_expr);
            println!("  └─> \x1b[36mRewrite:\x1b[0m '{}' -> '{}'", req.key_expr, new_key);
            Some(new_key)
        } else {
            None
        };
        println!(
            "  └─> \x1b[1mDecision:\x1b[0m {}",
            if allow { "\x1b[32mALLOW\x1b[0m" } else { "\x1b[31mDENY\x1b[0m" }
        );
        Ok(Response::new(AuthOnPublishResponse {
            allow,
            reason: if allow { "OK".into() } else { "Publish denied".into() },
            rewritten_key_expr,
        }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr: SocketAddr = "127.0.0.1:50051".parse()?;
    println!("\x1b[32m====================================================\x1b[0m");
    println!("\x1b[1;32m   Zenoh gRPC Auth Hook Server listening on http://{}\x1b[0m", addr);
    println!("\x1b[32m====================================================\x1b[0m");
    println!("Policy rules:");
    println!(" - Registers: Allowed (unless username == 'blocked')");
    println!(" - Subscribes/Publishes: Keys with 'deny' or 'forbidden' are rejected");
    println!("Waiting for hooks from zenohd...\n");

    tonic::transport::Server::builder()
        .add_service(ZenohHookServer::new(ExampleHookService))
        .serve(addr)
        .await?;

    Ok(())
}
