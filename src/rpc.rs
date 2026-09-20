
use crate::error::{RpcError, from_capnp_exception};
use crate::net::Conn;
use capnp::capability::{Client, FromClientHook, FromServer};
use capnp::message::ReaderOptions;
use capnp_rpc::{RpcSystem, twoparty};
use compio::io::compat::AsyncStream;
use compio::runtime::JoinHandle;
use error_stack::{Report, ResultExt};

pub use capnp_rpc::rpc_twoparty_capnp::Side;

pub fn default_reader_options() -> ReaderOptions {
    let mut options = ReaderOptions::new();
    options.traversal_limit_in_words(Some(1024 * 1024));
    options.nesting_limit(32);
    options
}

pub struct RpcSession<C: FromClientHook> {
    remote: C,
    driver: JoinHandle<Result<(), capnp::Error>>,
}

impl<C: FromClientHook> RpcSession<C> {
    pub fn remote(&self) -> &C {
        &self.remote
    }

    pub async fn wait(self) -> crate::error::Result<(), RpcError> {
        let Self { remote, driver } = self;
        drop(remote);
        match driver.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(from_capnp_exception(&e)),
            Err(panic) => Err(Report::new(RpcError::Setup)
                .attach(format!("rpc driver task panicked: {panic:?}"))),
        }
    }
}

pub fn spawn_session<C, S>(conn: Conn, side: Side, local_bootstrap: S) -> RpcSession<C>
where
    C: FromServer<S> + FromClientHook,
    S: 'static,
{
    spawn_session_with_options(conn, side, local_bootstrap, default_reader_options())
}

pub fn spawn_session_with_options<C, S>(
    conn: Conn,
    side: Side,
    local_bootstrap: S,
    reader_options: ReaderOptions,
) -> RpcSession<C>
where
    C: FromServer<S> + FromClientHook,
    S: 'static,
{
    let local_client: C = capnp_rpc::new_client(local_bootstrap);
    let untyped = Client {
        hook: local_client.into_client_hook(),
    };

    let reader = AsyncStream::new(conn.clone());
    let writer = AsyncStream::new(conn);
    let network = Box::new(twoparty::VatNetwork::new(
        reader,
        writer,
        side,
        reader_options,
    ));

    let mut rpc_system = RpcSystem::new(network, Some(untyped));
    let remote_side = match side {
        Side::Server => Side::Client,
        Side::Client => Side::Server,
    };
    let remote: C = rpc_system.bootstrap(remote_side);

    RpcSession {
        remote,
        driver: compio::runtime::spawn(rpc_system),
    }
}

pub async fn accept_session<C, S>(
    listener: &crate::net::Listener,
    mode: &crate::auth::handshake::HandshakeMode,
    schema: crate::auth::handshake::SchemaId,
    local_bootstrap: S,
) -> crate::error::Result<RpcSession<C>, RpcError>
where
    C: FromServer<S> + FromClientHook,
    S: 'static,
{
    let mut conn = listener.accept().await.change_context(RpcError::Setup)?;
    crate::auth::handshake::authenticate_server(&mut conn, mode, schema)
        .await
        .change_context(RpcError::Setup)?;
    Ok(spawn_session(conn, Side::Server, local_bootstrap))
}

pub async fn connect_session<C, S>(
    endpoint: &crate::endpoint::Endpoint,
    mode: &crate::auth::handshake::HandshakeMode,
    schema: crate::auth::handshake::SchemaId,
    local_bootstrap: S,
) -> crate::error::Result<RpcSession<C>, RpcError>
where
    C: FromServer<S> + FromClientHook,
    S: 'static,
{
    let mut conn = endpoint.connect().await.change_context(RpcError::Setup)?;
    crate::auth::handshake::authenticate_client(&mut conn, mode, schema)
        .await
        .change_context(RpcError::Setup)?;
    Ok(spawn_session(conn, Side::Client, local_bootstrap))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::handshake::{HandshakeMode, SchemaId, authenticate_client, authenticate_server};
    use crate::net::Listener;
    use capnp::capability::Rc;
    use std::cell::RefCell;
    use std::time::Duration;
    use testschema::echo_capnp::echo;

    struct EchoImpl {
        label: &'static str,
        pings: RefCell<Vec<String>>,
    }

    impl echo::Server for EchoImpl {
        async fn ping(
            self: Rc<Self>,
            params: echo::PingParams,
            mut results: echo::PingResults,
        ) -> std::result::Result<(), capnp::Error> {
            let msg = params.get()?.get_msg()?;
            let msg = msg.to_str()?;
            self.pings.borrow_mut().push(msg.to_string());
            results.get().set_reply(format!("{}: echo {}", self.label, msg));
            Ok(())
        }
    }

    async fn uds_pair(tag: &str) -> (Conn, Conn) {
        let path = std::env::temp_dir().join(format!(
            "ogurpchik-rpc-test-{tag}-{}.sock",
            std::process::id()
        ));
        let listener = Listener::bind_uds(&path).await.expect("bind failed");
        let (server, client) =
            futures::try_join!(listener.accept(), Conn::connect_uds(&path)).expect("join failed");
        drop(listener);
        (server, client)
    }

    fn spawn_agent(conn: Conn, side: Side, label: &'static str) -> RpcSession<echo::Client> {
        spawn_session(
            conn,
            side,
            EchoImpl {
                label,
                pings: RefCell::new(Vec::new()),
            },
        )
    }

    async fn ping(remote: &echo::Client, msg: &str) -> String {
        let mut req = remote.ping_request();
        req.get().set_msg(msg);
        let reply = req.send().promise.await.expect("rpc call failed");
        reply
            .get()
            .expect("no results")
            .get_reply()
            .expect("no reply field")
            .to_str()
            .expect("reply not utf8")
            .to_string()
    }

    #[compio::test]
    async fn handshake_then_rpc_roundtrip() {
        let (mut server_conn, mut client_conn) = uds_pair("hs").await;
        let mode = || HandshakeMode::hmac(b"secret".to_vec());

        let server_task = compio::runtime::spawn(async move {
            authenticate_server(&mut server_conn, &mode(), SchemaId(7))
                .await
                .expect("server handshake failed");
            let session = spawn_agent(server_conn, Side::Server, "host");
            compio::time::timeout(Duration::from_secs(5), session.wait())
                .await
                .expect("server session timed out")
                .expect("server session failed");
        });

        authenticate_client(&mut client_conn, &mode(), SchemaId(7))
            .await
            .expect("client handshake failed");
        let session = spawn_agent(client_conn, Side::Client, "agent");
        let reply = ping(session.remote(), "hello").await;
        assert_eq!(reply, "host: echo hello");
        drop(session);

        server_task.await.unwrap();
    }

    #[compio::test]
    async fn bidirectional_calls_over_one_connection() {
        let (server_conn, client_conn) = uds_pair("bidi").await;
        let server_session = spawn_agent(server_conn, Side::Server, "host");
        let client_session = spawn_agent(client_conn, Side::Client, "agent");

        let (from_host, from_agent) = futures::join!(
            ping(client_session.remote(), "down"),
            ping(server_session.remote(), "up"),
        );
        assert_eq!(from_host, "host: echo down");
        assert_eq!(from_agent, "agent: echo up");
    }

    #[compio::test]
    async fn unimplemented_method_reports_unimplemented() {
        let (server_conn, client_conn) = uds_pair("unimpl").await;
        let _server_session = spawn_agent(server_conn, Side::Server, "host");
        let client_session = spawn_agent(client_conn, Side::Client, "agent");

        let req = client_session.remote().stat_request();
        let result = req.send().promise.await;
        let err = match result {
            Ok(_) => panic!("unimplemented method must fail"),
            Err(e) => e,
        };
        assert!(matches!(err.kind, capnp::ErrorKind::Unimplemented));
    }

    #[compio::test]
    async fn client_disconnect_lets_server_finish() {
        let (server_conn, client_conn) = uds_pair("drop").await;
        let server_session = spawn_agent(server_conn, Side::Server, "host");

        {
            let client_session = spawn_agent(client_conn, Side::Client, "agent");
            ping(client_session.remote(), "one call then bye").await;
            drop(client_session);
        }

        compio::time::timeout(Duration::from_secs(5), server_session.wait())
            .await
            .expect("server session did not finish within timeout")
            .expect("server session failed");
    }
}
