use capnp::capability::Rc;
use capnp_rpc::rpc_capnp::message;
use compio::BufResult;
use compio::io::{AsyncRead, AsyncWriteExt};
use ogurpchik::net::{Conn, Listener};
use ogurpchik::rpc::{Side, spawn_session};
use std::time::Duration;
use testschema::echo_capnp::echo;

struct Mirror;

impl echo::Server for Mirror {
    async fn ping(
        self: Rc<Self>,
        params: echo::PingParams,
        mut results: echo::PingResults,
    ) -> Result<(), capnp::Error> {
        let msg = params.get()?.get_msg()?;
        results.get().set_reply(msg);
        Ok(())
    }
}

async fn uds_pair(tag: &str) -> (Conn, Conn) {
    let path = std::env::temp_dir().join(format!(
        "ogurpchik-transport-{tag}-{}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let listener = Listener::bind_uds(&path).await.expect("bind failed");
    let pair = futures::try_join!(listener.accept(), Conn::connect_uds(&path)).expect("join failed");
    drop(listener);
    let _ = std::fs::remove_file(&path);
    pair
}

fn text(len: usize, seed: usize) -> String {
    (0..len)
        .map(|i| char::from(b'a' + ((i * 7 + seed) % 26) as u8))
        .collect()
}

async fn echo_all(remote: &echo::Client, sizes: &[usize], seed: usize) {
    let calls = sizes.iter().enumerate().map(|(index, &len)| {
        let sent = text(len, seed + index);
        let mut request = remote.ping_request();
        request.get().set_msg(sent.as_str());
        async move {
            let reply = request.send().promise.await.expect("call failed");
            let echoed = reply.get().unwrap().get_reply().unwrap().to_string().unwrap();
            assert_eq!(echoed.len(), sent.len());
            assert!(echoed == sent, "reply to a {len}-byte ping came back different");
        }
    });
    futures::future::join_all(calls).await;
}

async fn heavy_traffic_both_ways(server: Conn, client: Conn) {
    let server = spawn_session::<echo::Client, _>(server, Side::Server, Mirror);
    let client = spawn_session::<echo::Client, _>(client, Side::Client, Mirror);
    let sizes: Vec<usize> = (0..120)
        .map(|i| [10, 5_000, 70_000, 300_000][i % 4] + i)
        .collect();
    compio::time::timeout(
        Duration::from_secs(60),
        futures::future::join(
            echo_all(client.remote(), &sizes, 0),
            echo_all(server.remote(), &sizes, 1),
        ),
    )
    .await
    .expect("traffic did not finish");
}

#[compio::test]
async fn tcp_carries_heavy_traffic_both_ways() {
    let listener = Listener::bind_tcp("127.0.0.1:0".parse().unwrap())
        .await
        .expect("bind failed");
    let Listener::Tcp(inner) = &listener else {
        unreachable!()
    };
    let addr = inner.local_addr().unwrap();
    let (server, client) =
        futures::try_join!(listener.accept(), Conn::connect_tcp(addr)).expect("join failed");
    heavy_traffic_both_ways(server, client).await;
}

#[compio::test]
async fn uds_carries_heavy_traffic_both_ways() {
    let (server, client) = uds_pair("heavy").await;
    heavy_traffic_both_ways(server, client).await;
}

#[cfg(windows)]
#[compio::test]
async fn npipe_carries_heavy_traffic_both_ways() {
    let name = format!("ogurpchik-transport-{}", std::process::id());
    let listener = Listener::bind_npipe(&name).await.expect("bind failed");
    let (server, client) =
        futures::try_join!(listener.accept(), Conn::connect_npipe(&name)).expect("join failed");
    heavy_traffic_both_ways(server, client).await;
}

#[compio::test]
async fn vsock_loopback_carries_heavy_traffic_both_ways() {
    const PORT: u32 = 22469;
    let listener = Listener::bind_vsock_loopback(PORT).expect("bind failed");
    let (server, client) = futures::try_join!(listener.accept(), Conn::connect_vsock_loopback(PORT))
        .expect("join failed");
    heavy_traffic_both_ways(server, client).await;
}

#[compio::test]
async fn more_queued_segments_than_one_batch_holds_all_arrive() {
    let (server, client) = uds_pair("batches").await;
    let _server = spawn_session::<echo::Client, _>(server, Side::Server, Mirror);
    let client = spawn_session::<echo::Client, _>(client, Side::Client, Mirror);
    let sizes: Vec<usize> = (0..300).map(|i| 5_000 + i).collect();
    compio::time::timeout(Duration::from_secs(20), echo_all(client.remote(), &sizes, 0))
        .await
        .expect("calls did not finish");
}

#[compio::test]
async fn an_oversized_frame_is_answered_with_abort_before_the_close() {
    let (server, mut raw) = uds_pair("abort").await;
    let session = spawn_session::<echo::Client, _>(server, Side::Server, Mirror);

    let mut header = 0u32.to_le_bytes().to_vec();
    header.extend_from_slice(&2_000_000u32.to_le_bytes());
    let BufResult(written, _) = raw.write_all(header).await;
    written.expect("write failed");

    let received = compio::time::timeout(Duration::from_secs(5), async {
        let mut received = Vec::new();
        loop {
            let BufResult(read, buf) = raw.read(Vec::with_capacity(64 * 1024)).await;
            match read {
                Ok(0) | Err(_) => return received,
                Ok(_) => received.extend_from_slice(&buf),
            }
        }
    })
    .await
    .expect("the peer never closed the connection");

    let mut rest = &received[..];
    let mut aborted = false;
    while let Some(frame) =
        capnp::serialize::try_read_message(&mut rest, Default::default()).expect("bad frame")
    {
        let root: message::Reader = frame.get_root().expect("bad rpc message");
        if let message::Abort(_) = root.which().expect("unknown rpc message") {
            aborted = true;
        }
    }
    assert!(aborted, "the connection closed without an Abort");

    let finished = compio::time::timeout(Duration::from_secs(5), session.wait())
        .await
        .expect("the session did not finish");
    assert!(finished.is_err());
}

#[compio::test]
async fn writes_to_a_vanished_peer_fail_the_calls() {
    let (client, raw) = uds_pair("vanished").await;
    let client = spawn_session::<echo::Client, _>(client, Side::Client, Mirror);
    drop(raw);

    let calls = (0..5).map(|_| {
        let mut request = client.remote().ping_request();
        request.get().set_msg("x".repeat(3_000_000).as_str());
        async move { request.send().promise.await.map(drop) }
    });
    let results = compio::time::timeout(Duration::from_secs(10), futures::future::join_all(calls))
        .await
        .expect("calls hung on a dead connection");
    assert!(results.iter().all(Result::is_err));
}
