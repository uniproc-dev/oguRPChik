
use testschema::echo_capnp::echo;
use ogurpchik::auth::handshake::{HandshakeMode, SchemaId, authenticate_client, authenticate_server};
use ogurpchik::net::{Conn, Listener};
use ogurpchik::rpc::{RpcSession, Side, spawn_session};
use capnp::capability::Rc;

const SCHEMA: SchemaId = SchemaId(0xbe4c);

pub struct EchoImpl;

impl echo::Server for EchoImpl {
    async fn ping(
        self: Rc<Self>,
        params: echo::PingParams,
        mut results: echo::PingResults,
    ) -> Result<(), capnp::Error> {
        let msg = params.get()?.get_msg()?;
        results.get().set_reply(msg.to_str()?.to_string());
        Ok(())
    }
}

pub const TRANSPORTS: &[&str] = if cfg!(windows) {
    &["tcp", "uds", "npipe"]
} else {
    &["tcp", "uds"]
};

pub async fn bind(kind: &str) -> (Listener, Box<dyn Fn() -> ConnConnect>) {
    match kind {
        "tcp" => {
            let listener = Listener::bind_tcp("127.0.0.1:0".parse().unwrap())
                .await
                .expect("bind failed");
            let Listener::Tcp(inner) = &listener else {
                unreachable!()
            };
            let addr = inner.local_addr().unwrap();
            (listener, Box::new(move || ConnConnect::Tcp(addr)))
        }
        "uds" => {
            let path = std::env::temp_dir().join(format!(
                "ogurpchik-bench-{kind}-{}.sock",
                std::process::id()
            ));
            let listener = Listener::bind_uds(&path).await.expect("bind failed");
            (listener, Box::new(move || ConnConnect::Uds(path.clone())))
        }
        #[cfg(windows)]
        "npipe" => {
            let name = format!("ogurpchik-bench-{}", std::process::id());
            let listener = Listener::bind_npipe(&name).await.expect("bind failed");
            (listener, Box::new(move || ConnConnect::Npipe(name.clone())))
        }
        other => panic!("unknown transport {other}"),
    }
}

pub enum ConnConnect {
    Tcp(std::net::SocketAddr),
    Uds(std::path::PathBuf),
    #[cfg(windows)]
    Npipe(String),
}

impl ConnConnect {
    pub async fn connect(self) -> Conn {
        match self {
            Self::Tcp(addr) => Conn::connect_tcp(addr).await.expect("connect failed"),
            Self::Uds(path) => Conn::connect_uds(&path).await.expect("connect failed"),
            #[cfg(windows)]
            Self::Npipe(name) => Conn::connect_npipe(&name).await.expect("connect failed"),
        }
    }
}

pub fn spawn_server(listener: Listener) {
    compio::runtime::spawn(async move {
        let mut conn = listener.accept().await.expect("accept failed");
        authenticate_server(&mut conn, &HandshakeMode::hmac(b"bench".to_vec()), SCHEMA)
            .await
            .expect("server handshake failed");
        let session = spawn_session::<echo::Client, _>(conn, Side::Server, EchoImpl);
        let _ = session.wait().await;
    })
    .detach();
}

pub async fn client_session(connect: ConnConnect) -> RpcSession<echo::Client> {
    let mut conn = connect.connect().await;
    authenticate_client(&mut conn, &HandshakeMode::hmac(b"bench".to_vec()), SCHEMA)
        .await
        .expect("client handshake failed");
    spawn_session(conn, Side::Client, EchoImpl)
}

pub async fn ping(session: &RpcSession<echo::Client>) {
    let mut req = session.remote().ping_request();
    req.get().set_msg("ping");
    req.send().promise.await.expect("ping failed");
}
