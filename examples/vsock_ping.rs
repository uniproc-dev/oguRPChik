use capnp::capability::Rc;
use ogurpchik::auth::handshake::{HandshakeMode, SchemaId};
use ogurpchik::endpoint::Endpoint;
use ogurpchik::net::vsock::VsockTarget;
use ogurpchik::rpc::{accept_session, connect_session};
use testschema::echo_capnp::echo;

const SCHEMA: SchemaId = SchemaId(0xec40);

struct EchoImpl;

impl echo::Server for EchoImpl {
    async fn ping(
        self: Rc<Self>,
        params: echo::PingParams,
        mut results: echo::PingResults,
    ) -> Result<(), capnp::Error> {
        let msg = params.get()?.get_msg()?;
        let msg = msg.to_str()?;
        let who = if cfg!(windows) { "windows host" } else { "wsl guest" };
        results.get().set_reply(format!("{who} echo: {msg}"));
        Ok(())
    }
}

#[compio::main]
async fn main() {
    let mode = std::env::args()
        .nth(1)
        .expect("usage: vsock_ping --listen|--connect <port>");
    let port: u32 = std::env::args()
        .nth(2)
        .and_then(|p| p.parse().ok())
        .expect("port must be a number");
    let handshake = HandshakeMode::hmac(b"wsl-vsock-test".to_vec());

    match mode.as_str() {
        "--listen" => {
            let endpoint = Endpoint::Vsock {
                target: VsockTarget::Cid(u32::MAX),
                port,
            };
            let listener = endpoint.listen().await.expect("listen failed");
            println!("listening on vsock port {port} ({})", endpoint.kind());
            let session = accept_session::<echo::Client, _>(&listener, &handshake, SCHEMA, EchoImpl)
                .await
                .expect("accept_session failed");
            println!("peer connected and authenticated, serving");
            let _ = session.wait().await;
            println!("session ended");
        }
        "--connect" => {
            #[cfg(windows)]
            let endpoint = Endpoint::vsock_to_best_vm(port).expect("failed to resolve best vm");
            #[cfg(not(windows))]
            let endpoint = Endpoint::vsock_to_host(port);
            let session = connect_session::<echo::Client, _>(&endpoint, &handshake, SCHEMA, EchoImpl)
                .await
                .expect("connect_session failed");
            let mut req = session.remote().ping_request();
            req.get().set_msg("ping over hyper-v vsock");
            let reply = req.send().promise.await.expect("ping failed");
            let reply = reply.get().unwrap().get_reply().unwrap().to_str().unwrap();
            println!("reply: {reply}");
        }
        other => panic!("unknown mode {other}; usage: vsock_ping --listen|--connect <port>"),
    }
}
