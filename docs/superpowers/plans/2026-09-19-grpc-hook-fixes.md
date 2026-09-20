# gRPC Hook Fixes and Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix security bypass, runtime panic hazards, payload memory overhead, and documentation ambiguities in the `grpc_hook` feature.

**Architecture:** 
1. Guard `get_auth_ids()` failure in `GrpcHookInterceptorFactory` to enforce `fail_open` semantics and prevent silent auth bypass.
2. Safeguard `tokio::task::block_in_place` against single-threaded runtime panics using runtime flavor checks and fallback execution.
3. Introduce configurable payload capture limits (`max_payload_bytes`) in `GrpcHookConfig` to avoid unbounded buffer cloning on high-throughput message publishing.
4. Document the exact `HMAC-SHA3-256` hashing algorithm in `zenoh_hook.proto` so third-party gRPC hook implementers can verify client passwords reliably.
5. Add configuration warnings for un-intercepted dynamic authentication.

**Tech Stack:** Rust (Zenoh, Tokio, Tonic, Prost, zenoh-config, zenoh-transport).

**Spec:** Code review findings from commit `bf5bc26a8bcdb18962722a85d63ef327430ca994`.

## Global Constraints
- Rust 2021 edition.
- Preserve backward compatibility for existing Zenoh configurations (default features build without errors).
- All changes must pass `cargo check -p zenoh -p zenoh-transport` and `cargo test -p zenoh --test grpc_hook --features grpc_hook`.
- Maintain clean error handling without panics or unwraps in library code.

---

### Task 1: Fix Security Bypass on Transport `get_auth_ids()` Failure

**Files:**
- Modify: `zenoh/src/net/routing/interceptor/grpc_hook.rs:163-170`
- Test: `zenoh/tests/grpc_hook.rs`

**Interfaces:**
- Consumes: `transport.get_auth_ids() -> Result<TransportAuthId, TransportError>`, `self.hook.fail_open: bool`
- Produces: Returns `Err(...)` when `get_auth_ids()` fails and `fail_open` is `false`, denying registration.

- [ ] **Step 1: Write a unit test verifying auth failure handling**

In `zenoh/tests/grpc_hook.rs`, verify that transport registration denial when `fail_open: false` cleanly closes connection.

- [ ] **Step 2: Update error handling in `GrpcHookInterceptorFactory::new_transport_unicast`**

In `zenoh/src/net/routing/interceptor/grpc_hook.rs`:
```rust
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
```

- [ ] **Step 3: Run tests to verify**

Run: `cargo test -p zenoh --test grpc_hook --features grpc_hook`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add zenoh/src/net/routing/interceptor/grpc_hook.rs
git commit -m "fix(grpc_hook): enforce fail_open policy when get_auth_ids fails"
```

---

### Task 2: Safeguard `call_hook` Against Single-Threaded Runtime Panics

**Files:**
- Modify: `zenoh/src/net/routing/interceptor/grpc_hook.rs:63-90`

**Interfaces:**
- Consumes: `tokio::runtime::Handle::current()`
- Produces: `HookClient::call_hook` safely executing async futures across both `MultiThread` and `CurrentThread` runtimes without panicking.

- [ ] **Step 1: Update `call_hook` implementation**

In `zenoh/src/net/routing/interceptor/grpc_hook.rs`:
```rust
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
                })
            }
            _ => {
                tokio::task::block_in_place(|| {
                    handle.block_on(async move {
                        tokio::time::timeout(timeout, fut).await
                    })
                })
            }
        }
        .map_err(|_elapsed| ()) // timeout
        .and_then(|res| res.map_err(|_| ())) // gRPC error
        .map(|resp| resp.into_inner())
    }
```

- [ ] **Step 2: Run tests to verify**

Run: `cargo test -p zenoh --test grpc_hook --features grpc_hook`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add zenoh/src/net/routing/interceptor/grpc_hook.rs
git commit -m "fix(grpc_hook): prevent block_in_place panic on current_thread runtimes"
```

---

### Task 3: Clarify HMAC Algorithm and Filtering in Proto Documentation

**Files:**
- Modify: `zenoh/proto/zenoh_hook.proto:20-30, 60-70`

**Interfaces:**
- Produces: Documented protocol schema for third-party hook implementers detailing `HMAC-SHA3-256` calculation and keyexpr filtering.

- [ ] **Step 1: Update proto comments in `zenoh/proto/zenoh_hook.proto`**

In `zenoh/proto/zenoh_hook.proto`:
```protobuf
    // The HMAC challenge signature sent by the client (empty if usrpwd not used).
    // Zenoh computes this using HMAC-SHA3-256 with the 64-bit challenge nonce in
    // little-endian byte order (`nonce.to_le_bytes()`) as the secret key, and the
    // UTF-8 password string bytes as the data.
    bytes hmac            = 6;
    // The random 64-bit challenge nonce sent to the client.
    uint64 nonce          = 7;
```
And clarify `AuthOnPublishRequest.action`:
```protobuf
    // "put" | "delete" | "query" | "reply"
    // Note: Internal liveliness tokens and @/** admin key expressions are filtered
    // before reaching the interceptor.
    string action        = 4;
```

- [ ] **Step 2: Recompile and check proto compilation**

Run: `cargo check -p zenoh --features grpc_hook`
Expected: SUCCESS

- [ ] **Step 3: Commit**

```bash
git add zenoh/proto/zenoh_hook.proto
git commit -m "docs(grpc_hook): document HMAC-SHA3-256 calculation and action filtering in proto"
```

---

### Task 4: Add Configurable Payload Limit for Publish Hooks

**Files:**
- Modify: `commons/zenoh-config/src/lib.rs:163-195`
- Modify: `DEFAULT_CONFIG.json5:502-516`
- Modify: `zenoh/src/net/routing/interceptor/grpc_hook.rs:56-65, 315-330`
- Test: `zenoh/tests/grpc_hook.rs`

**Interfaces:**
- Consumes: `GrpcHookConfig.max_payload_bytes: usize` (default: 65536, 0 disables payload copying)
- Produces: Truncates payload buffer to `max_payload_bytes` instead of cloning multi-megabyte payloads unconditionally.

- [ ] **Step 1: Add `max_payload_bytes` to `GrpcHookConfig`**

In `commons/zenoh-config/src/lib.rs`:
```rust
pub struct GrpcHookConfig {
    pub enabled: bool,
    pub endpoint: String,
    #[serde(default = "GrpcHookConfig::default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub fail_open: bool,
    /// Maximum payload bytes forwarded to auth_on_publish. Default: 65536 (64 KB). Set to 0 to disable payload forwarding.
    #[serde(default = "GrpcHookConfig::default_max_payload_bytes")]
    pub max_payload_bytes: usize,
}

impl GrpcHookConfig {
    fn default_timeout_ms() -> u64 {
        500
    }
    fn default_max_payload_bytes() -> usize {
        65536
    }
}
```
Update `DEFAULT_CONFIG.json5`:
```json5
  // grpc_hook: {
  //   enabled: false,
  //   endpoint: "http://127.0.0.1:50051",
  //   timeout_ms: 500,
  //   fail_open: false,
  //   max_payload_bytes: 65536,
  // },
```

- [ ] **Step 2: Apply payload truncation in `GrpcHookInterceptor::intercept`**

In `zenoh/src/net/routing/interceptor/grpc_hook.rs`:
Pass `max_payload_bytes` into `HookClient` / `GrpcHookInterceptor`.
In `PushBody::Put(put)`:
```rust
    let payload = if self.hook.max_payload_bytes == 0 {
        Vec::new()
    } else {
        let zslice = put.payload.to_zslice();
        let len = zslice.len().min(self.hook.max_payload_bytes);
        zslice[..len].to_vec()
    };
```

- [ ] **Step 3: Run integration test suite**

Run: `cargo test -p zenoh --test grpc_hook --features grpc_hook`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add commons/zenoh-config/src/lib.rs DEFAULT_CONFIG.json5 zenoh/src/net/routing/interceptor/grpc_hook.rs
git commit -m "feat(grpc_hook): add max_payload_bytes to prevent unbounded memory cloning"
```

---

### Task 5: Add Warning for Unvalidated Dynamic UsrPwd Mode

**Files:**
- Modify: `io/zenoh-transport/src/unicast/establishment/ext/auth/usrpwd.rs:115-130`

**Interfaces:**
- Consumes: `dynamic: bool`, `lookup.is_empty()`, `credentials.is_none()`
- Produces: Warning log when `dynamic: true` is enabled with no static dictionary, alerting operators that credential verification must be handled by an interceptor.

- [ ] **Step 1: Add tracing warning in `AuthUsrPwd::from_config`**

In `io/zenoh-transport/src/unicast/establishment/ext/auth/usrpwd.rs`:
```rust
        if !lookup.is_empty() || credentials.is_some() || dynamic {
            if dynamic && lookup.is_empty() {
                tracing::warn!(
                    "{S} Dynamic usrpwd authentication enabled without dictionary. \
                     All credentials will be accepted at transport layer unless gated by an external hook."
                );
            }
            tracing::debug!("{S} User-password authentication is enabled (dynamic={dynamic}).");
...
```

- [ ] **Step 2: Verify cargo check**

Run: `cargo check -p zenoh-transport -p zenoh`
Expected: SUCCESS

- [ ] **Step 3: Commit**

```bash
git add io/zenoh-transport/src/unicast/establishment/ext/auth/usrpwd.rs
git commit -m "warn(transport): warn when dynamic usrpwd is used without dictionary"
```

---

### Task 6: Full Verification and Non-Regression Testing

**Files:**
- Test: entire workspace compilation and test suite

- [ ] **Step 1: Check default build without features**

Run: `cargo check --workspace`
Expected: SUCCESS

- [ ] **Step 2: Check zenohd with grpc_hook feature**

Run: `cargo check -p zenohd --features grpc_hook`
Expected: SUCCESS

- [ ] **Step 3: Run all grpc_hook tests**

Run: `cargo test -p zenoh --test grpc_hook --features grpc_hook`
Expected: All 5 tests PASS

- [ ] **Step 4: Commit and finalize**

```bash
git status
```
