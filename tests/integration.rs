
use testschema::echo_capnp::echo;
use ogurpchik::auth::handshake::{
    ConnectionGate, ConnectionMode, HandshakeMode, SchemaId, authenticate_client,
    authenticate_server, reject_connection,
};
use ogurpchik::endpoint::Endpoint;
use ogurpchik::error::{HandshakeError, RpcError};
use ogurpchik::net::{Conn, Listener};
use ogurpchik::rpc::{RpcSession, Side, spawn_session};
use capnp::capability::Rc;

struct EchoImpl;

impl echo::Server for EchoImpl {
    async fn ping(
        self: Rc<Self>,
        params: echo::PingParams,
        mut results: echo::PingResults,
    ) -> Result<(), capnp::Error> {
        let msg = params.get()?.get_msg()?;
        results
            .get()
            .set_reply(format!("echo {}", msg.to_str()?));
        Ok(())
    }
}

const SCHEMA: SchemaId = SchemaId(0x17);

fn hmac() -> HandshakeMode {
    HandshakeMode::hmac(b"integration-secret".to_vec())
}

async fn serve_one(listener: &Listener) -> RpcSession<echo::Client> {
    ogurpchik::rpc::accept_session(listener, &hmac(), SCHEMA, EchoImpl)
        .await
        .expect("accept_session failed")
}

async fn connect_client(conn: Conn) -> RpcSession<echo::Client> {
    let mut conn = conn;
    authenticate_client(&mut conn, &hmac(), SCHEMA)
        .await
        .expect("client handshake failed");
    spawn_session(conn, Side::Client, EchoImpl)
}

async fn ping(session: &RpcSession<echo::Client>, msg: &str) -> String {
    let mut req = session.remote().ping_request();
    req.get().set_msg(msg);
    let reply = req.send().promise.await.expect("ping failed");
    reply
        .get()
        .unwrap()
        .get_reply()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

async fn full_stack_ping_pong(listener: Listener, connect: impl std::future::Future<Output = Conn>) {
    let server_task = compio::runtime::spawn(async move {
        let session = serve_one(&listener).await;
        compio::time::timeout(std::time::Duration::from_secs(5), session.wait())
            .await
            .ok();
    });

    let client_session = connect_client(connect.await).await;
    assert_eq!(ping(&client_session, "ping").await, "echo ping");
    drop(client_session);
    server_task.await.unwrap();
}

#[compio::test]
async fn tcp_full_stack() {
    let listener = Listener::bind_tcp("127.0.0.1:0".parse().unwrap())
        .await
        .expect("bind failed");
    let Listener::Tcp(inner) = &listener else {
        unreachable!()
    };
    let addr = inner.local_addr().unwrap();
    full_stack_ping_pong(listener, async move {
        Conn::connect_tcp(addr).await.expect("connect failed")
    })
    .await;
}

#[compio::test]
async fn tcp_facade_roundtrip() {
    use ogurpchik::rpc::{accept_session, connect_session};

    let endpoint = Endpoint::Tcp("127.0.0.1:0".parse().unwrap());
    let listener = endpoint.listen().await.expect("listen failed");
    let Listener::Tcp(inner) = &listener else {
        unreachable!()
    };
    let endpoint = Endpoint::Tcp(inner.local_addr().unwrap());

    let server_task = compio::runtime::spawn(async move {
        let session = accept_session::<echo::Client, _>(&listener, &hmac(), SCHEMA, EchoImpl)
            .await
            .expect("accept_session failed");
        compio::time::timeout(std::time::Duration::from_secs(5), session.wait())
            .await
            .ok();
    });

    let session = connect_session::<echo::Client, _>(&endpoint, &hmac(), SCHEMA, EchoImpl)
        .await
        .expect("connect_session failed");
    assert_eq!(ping(&session, "facade").await, "echo facade");
    drop(session);
    server_task.await.unwrap();
}

#[compio::test]
async fn facade_surfaces_schema_mismatch() {
    use ogurpchik::rpc::{accept_session, connect_session};

    let endpoint = Endpoint::Tcp("127.0.0.1:0".parse().unwrap());
    let listener = endpoint.listen().await.expect("listen failed");
    let Listener::Tcp(inner) = &listener else {
        unreachable!()
    };
    let endpoint = Endpoint::Tcp(inner.local_addr().unwrap());

    let server_task = compio::runtime::spawn(async move {
        accept_session::<echo::Client, _>(&listener, &hmac(), SchemaId(1), EchoImpl)
            .await
            .map(drop)
    });

    let err = connect_session::<echo::Client, _>(&endpoint, &hmac(), SchemaId(2), EchoImpl)
        .await
        .map(drop)
        .expect_err("a client built against another schema must not connect");
    assert!(matches!(err.current_context(), RpcError::Setup));
    assert!(matches!(
        err.downcast_ref::<HandshakeError>(),
        Some(HandshakeError::SchemaMismatch)
    ));

    let server_err = server_task
        .await
        .unwrap()
        .expect_err("the server must refuse it too");
    assert!(matches!(
        server_err.downcast_ref::<HandshakeError>(),
        Some(HandshakeError::SchemaMismatch)
    ));
}

#[compio::test]
async fn uds_full_stack() {
    let path = std::env::temp_dir().join(format!("ogurpchik-it-{}.sock", std::process::id()));
    let listener = Listener::bind_uds(&path).await.expect("bind failed");
    full_stack_ping_pong(listener, async move {
        Conn::connect_uds(&path).await.expect("connect failed")
    })
    .await;
}

#[cfg(windows)]
#[compio::test]
async fn npipe_full_stack() {
    let name = format!("ogurpchik-it-{}", std::process::id());
    let listener = Listener::bind_npipe(&name).await.expect("bind failed");
    full_stack_ping_pong(listener, async move {
        Conn::connect_npipe(&name).await.expect("connect failed")
    })
    .await;
}

#[compio::test]
async fn vsock_loopback_full_stack() {
    const PORT: u32 = 22468;
    let listener = Listener::bind_vsock_loopback(PORT).expect("bind failed");
    full_stack_ping_pong(listener, async move {
        Conn::connect_vsock_loopback(PORT)
            .await
            .expect("connect failed")
    })
    .await;
}

#[compio::test]
async fn wrong_hmac_is_rejected() {
    let endpoint = Endpoint::Tcp("127.0.0.1:0".parse().unwrap());
    let listener = endpoint.listen().await.expect("listen failed");
    let Listener::Tcp(inner) = &listener else {
        unreachable!()
    };
    let addr = inner.local_addr().unwrap();

    let server_task = compio::runtime::spawn(async move {
        let mut conn = listener.accept().await.expect("accept failed");
        authenticate_server(&mut conn, &hmac(), SCHEMA).await
    });

    let mut conn = Conn::connect_tcp(addr).await.expect("connect failed");
    let client_result =
        authenticate_client(&mut conn, &HandshakeMode::hmac(b"wrong".to_vec()), SCHEMA).await;
    let client_err = client_result.expect_err("client must be rejected");
    assert!(matches!(
        client_err.current_context(),
        HandshakeError::Rejected
    ));

    let server_err = server_task
        .await
        .unwrap()
        .expect_err("server must reject");
    assert!(matches!(
        server_err.current_context(),
        HandshakeError::InvalidProof
    ));
}

#[compio::test]
async fn one_to_one_rejects_second_client() {
    let endpoint = Endpoint::Tcp("127.0.0.1:0".parse().unwrap());
    let listener = endpoint.listen().await.expect("listen failed");
    let Listener::Tcp(inner) = &listener else {
        unreachable!()
    };
    let addr = inner.local_addr().unwrap();

    let server_task = compio::runtime::spawn(async move {
        let gate = ConnectionGate::new(ConnectionMode::OneToOne);
        let mut first = listener.accept().await.expect("accept first failed");
        let _lease = gate.try_acquire().expect("first client must acquire the gate");
        authenticate_server(&mut first, &hmac(), SCHEMA)
            .await
            .expect("first handshake failed");
        let first_session = spawn_session::<echo::Client, _>(
            first,
            Side::Server,
            EchoImpl,
        );

        let mut second = listener.accept().await.expect("accept second failed");
        assert!(gate.try_acquire().is_none());
        reject_connection(&mut second, "one-to-one server is busy")
            .await
            .expect("reject failed");

        compio::time::timeout(std::time::Duration::from_secs(5), first_session.wait())
            .await
            .ok();
    });

    let first_session = connect_client(Conn::connect_tcp(addr).await.expect("connect failed")).await;
    assert_eq!(ping(&first_session, "first").await, "echo first");

    let mut second_conn = Conn::connect_tcp(addr).await.expect("connect failed");
    let second_result = authenticate_client(&mut second_conn, &hmac(), SCHEMA).await;
    let err = second_result.expect_err("second client must be rejected");
    assert!(matches!(
        err.current_context(),
        HandshakeError::Rejected
    ));

    drop(first_session);
    server_task.await.unwrap();
}

#[compio::test]
async fn oversized_message_trips_traversal_limit() {
    use ogurpchik::rpc::spawn_session_with_options;

    let tiny_limits = || {
        let mut options = capnp::message::ReaderOptions::new();
        options.traversal_limit_in_words(Some(8 * 1024));
        options
    };
    let handler_ran = std::rc::Rc::new(std::cell::Cell::new(false));

    let endpoint = Endpoint::Tcp("127.0.0.1:0".parse().unwrap());
    let listener = endpoint.listen().await.expect("listen failed");
    let Listener::Tcp(inner) = &listener else {
        unreachable!()
    };
    let addr = inner.local_addr().unwrap();

    let server_task = compio::runtime::spawn({
        let handler_ran = handler_ran.clone();
        async move {
            struct TrackImpl(std::rc::Rc<std::cell::Cell<bool>>);
            impl echo::Server for TrackImpl {
                async fn ping(
                    self: Rc<Self>,
                    _params: echo::PingParams,
                    _results: echo::PingResults,
                ) -> Result<(), capnp::Error> {
                    self.0.set(true);
                    Ok(())
                }
            }

            let mut conn = listener.accept().await.expect("accept failed");
            authenticate_server(&mut conn, &hmac(), SCHEMA)
                .await
                .expect("server handshake failed");
            let session = spawn_session_with_options::<echo::Client, _>(
                conn,
                Side::Server,
                TrackImpl(handler_ran),
                tiny_limits(),
            );
            compio::time::timeout(std::time::Duration::from_secs(5), session.wait())
                .await
                .expect("server session hung: the oversized message got through")
                .ok();
        }
    });

    let mut conn = Conn::connect_tcp(addr).await.expect("connect failed");
    authenticate_client(&mut conn, &hmac(), SCHEMA)
        .await
        .expect("client handshake failed");
    let client_session = spawn_session_with_options::<echo::Client, _>(
        conn,
        Side::Client,
        EchoImpl,
        tiny_limits(),
    );

    let big = "x".repeat(1024 * 1024);
    let mut req = client_session.remote().ping_request();
    req.get().set_msg(&big[..]);
    let _ = req.send();

    server_task.await.unwrap();
    assert!(
        !handler_ran.get(),
        "handler ran: the traversal limit was not enforced"
    );
    drop(client_session);
}
