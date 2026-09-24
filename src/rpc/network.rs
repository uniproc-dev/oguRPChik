use super::frame::{Batch, Inbound, OutMessage};
use crate::net::Conn;
use capnp::Error;
use capnp::capability::Promise;
use capnp::message::{Builder, HeapAllocator, Reader, ReaderOptions};
use capnp::serialize::OwnedSegments;
use capnp_rpc::rpc_twoparty_capnp::Side;
use compio::BufResult;
use compio::io::{AsyncWrite, AsyncWriteExt};
use futures::channel::{mpsc, oneshot};
use futures::future::Shared;
use futures::{FutureExt, StreamExt, TryFutureExt};
use std::cell::RefCell;
use std::rc::{Rc, Weak};

const STAGING_CAPACITY: usize = 64 * 1024;
const INLINE_LIMIT: usize = 4 * 1024;
const BATCH_CHUNKS: usize = 64;
const BATCH_BYTES: usize = 1024 * 1024;

enum Item {
    Message(OutMessage, oneshot::Sender<()>),
    Done(capnp::Result<()>, oneshot::Sender<()>),
}

fn writer_stopped() -> Error {
    Error::disconnected("the connection's writer has stopped".into())
}

struct Outgoing {
    message: Builder<HeapAllocator>,
    queue: mpsc::UnboundedSender<Item>,
}

impl capnp_rpc::OutgoingMessage for Outgoing {
    fn get_body(&mut self) -> capnp::Result<capnp::any_pointer::Builder<'_>> {
        self.message.get_root()
    }

    fn get_body_as_reader(&self) -> capnp::Result<capnp::any_pointer::Reader<'_>> {
        self.message.get_root_as_reader()
    }

    fn send(self: Box<Self>) -> (Promise<(), Error>, OutMessage) {
        let Self { message, queue } = *self;
        let message = Rc::new(message);
        let (written, on_written) = oneshot::channel();
        let _ = queue.unbounded_send(Item::Message(message.clone(), written));
        (
            Promise::from_future(on_written.map_err(|_| writer_stopped())),
            message,
        )
    }

    fn take(self: Box<Self>) -> Builder<HeapAllocator> {
        self.message
    }

    fn size_in_words(&self) -> usize {
        self.message.size_in_words()
    }
}

struct Incoming(Reader<OwnedSegments>);

impl capnp_rpc::IncomingMessage for Incoming {
    fn get_body(&self) -> capnp::Result<capnp::any_pointer::Reader<'_>> {
        self.0.get_root()
    }
}

type Input = Rc<RefCell<Option<(Conn, Inbound)>>>;

struct State {
    input: Input,
    queue: mpsc::UnboundedSender<Item>,
    peer: Side,
    on_disconnect: Option<oneshot::Sender<()>>,
}

impl Drop for State {
    fn drop(&mut self) {
        if let Some(disconnected) = self.on_disconnect.take() {
            let _ = disconnected.send(());
        }
    }
}

struct Connection {
    state: Rc<RefCell<State>>,
}

impl capnp_rpc::Connection<Side> for Connection {
    fn get_peer_vat_id(&self) -> Side {
        self.state.borrow().peer
    }

    fn new_outgoing_message(
        &mut self,
        first_segment_word_size: u32,
    ) -> Box<dyn capnp_rpc::OutgoingMessage> {
        Box::new(Outgoing {
            message: Builder::new(
                HeapAllocator::new().first_segment_words(first_segment_word_size),
            ),
            queue: self.state.borrow().queue.clone(),
        })
    }

    fn receive_incoming_message(
        &mut self,
    ) -> Promise<Option<Box<dyn capnp_rpc::IncomingMessage>>, Error> {
        let slot = self.state.borrow().input.clone();
        let Some((mut conn, mut inbound)) = slot.borrow_mut().take() else {
            return Promise::err(Error::failed(
                "a receive is already in progress on this connection".into(),
            ));
        };
        Promise::from_future(async move {
            let message = inbound.next(&mut conn).await?;
            *slot.borrow_mut() = Some((conn, inbound));
            Ok(message.map(|message| {
                Box::new(Incoming(message)) as Box<dyn capnp_rpc::IncomingMessage>
            }))
        })
    }

    fn shutdown(&mut self, result: capnp::Result<()>) -> Promise<(), Error> {
        let (finished, on_finished) = oneshot::channel();
        let _ = self
            .state
            .borrow()
            .queue
            .unbounded_send(Item::Done(result, finished));
        Promise::from_future(on_finished.map_err(|_| writer_stopped()))
    }
}

/// A two-party capnp-rpc vat network that reads and writes a [`Conn`] directly,
/// wire-compatible with `capnp_rpc::twoparty`.
pub struct VatNetwork {
    connection: Option<Connection>,
    state: Weak<RefCell<State>>,
    driver: Shared<Promise<(), Error>>,
    side: Side,
}

impl VatNetwork {
    pub fn new(conn: Conn, side: Side, options: ReaderOptions) -> Self {
        let (disconnected, on_disconnect) = oneshot::channel::<()>();
        let (queue, items) = mpsc::unbounded();
        let writer = write_loop(conn.clone(), items);
        let driver = Promise::from_future(async move {
            let written = writer.await;
            let _ = on_disconnect.await;
            written
        })
        .shared();

        let peer = match side {
            Side::Server => Side::Client,
            Side::Client => Side::Server,
        };
        let state = Rc::new(RefCell::new(State {
            input: Rc::new(RefCell::new(Some((
                conn,
                Inbound::new(options, STAGING_CAPACITY),
            )))),
            queue,
            peer,
            on_disconnect: Some(disconnected),
        }));
        Self {
            state: Rc::downgrade(&state),
            connection: Some(Connection { state }),
            driver,
            side,
        }
    }
}

impl capnp_rpc::VatNetwork<Side> for VatNetwork {
    fn connect(&mut self, host_id: Side) -> Option<Box<dyn capnp_rpc::Connection<Side>>> {
        if host_id == self.side {
            return None;
        }
        let state = self
            .state
            .upgrade()
            .expect("tried to reconnect a disconnected vat network");
        Some(Box::new(Connection { state }))
    }

    fn accept(&mut self) -> Promise<Box<dyn capnp_rpc::Connection<Side>>, Error> {
        match self.connection.take() {
            Some(connection) => {
                Promise::ok(Box::new(connection) as Box<dyn capnp_rpc::Connection<Side>>)
            }
            None => Promise::from_future(futures::future::pending()),
        }
    }

    fn drive_until_shutdown(&mut self) -> Promise<(), Error> {
        Promise::from_future(self.driver.clone())
    }
}

async fn write_loop(mut conn: Conn, mut items: mpsc::UnboundedReceiver<Item>) -> capnp::Result<()> {
    let mut batch = Batch::new(INLINE_LIMIT);
    let mut written = Vec::new();
    while let Some(first) = items.next().await {
        let mut next = Some(first);
        let mut done = None;
        while let Some(item) = next.take() {
            match item {
                Item::Message(message, on_written) => {
                    batch.push(&message);
                    written.push(on_written);
                }
                Item::Done(result, on_finished) => {
                    done = Some((result, on_finished));
                    break;
                }
            }
            if batch.chunk_count() >= BATCH_CHUNKS || batch.byte_count() >= BATCH_BYTES {
                break;
            }
            next = items.try_recv().ok();
        }

        if !batch.is_empty() {
            let BufResult(result, chunks) = conn.write_vectored_all(batch.take()).await;
            batch.recycle(chunks);
            result?;
            conn.flush().await?;
            for on_written in written.drain(..) {
                let _ = on_written.send(());
            }
        }
        if let Some((result, on_finished)) = done {
            let _ = on_finished.send(());
            return result;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::Listener;
    use crate::rpc::{default_reader_options, spawn_session};
    use capnp_rpc::{RpcSystem, twoparty};
    use compio::io::compat::AsyncStream;
    use proptest::prelude::*;
    use testschema::echo_capnp::echo;

    struct Mirror;

    impl echo::Server for Mirror {
        async fn ping(
            self: capnp::capability::Rc<Self>,
            params: echo::PingParams,
            mut results: echo::PingResults,
        ) -> Result<(), Error> {
            let msg = params.get()?.get_msg()?;
            results.get().set_reply(msg);
            Ok(())
        }
    }

    async fn uds_pair() -> (Conn, Conn) {
        let path = std::env::temp_dir().join(format!(
            "ogurpchik-network-{}-{}.sock",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let listener = Listener::bind_uds(&path).await.expect("bind failed");
        let (server, client) =
            futures::try_join!(listener.accept(), Conn::connect_uds(&path)).expect("join failed");
        drop(listener);
        let _ = std::fs::remove_file(&path);
        (server, client)
    }

    fn stock(conn: Conn, side: Side) -> echo::Client {
        let local: echo::Client = capnp_rpc::new_client(Mirror);
        let network = twoparty::VatNetwork::new(
            AsyncStream::new(conn.clone()),
            AsyncStream::new(conn),
            side,
            default_reader_options(),
        );
        let mut system = RpcSystem::new(Box::new(network), Some(local.client));
        let remote = system.bootstrap(match side {
            Side::Server => Side::Client,
            Side::Client => Side::Server,
        });
        compio::runtime::spawn(system).detach();
        remote
    }

    fn text(len: usize, seed: usize) -> String {
        (0..len)
            .map(|i| char::from(b'a' + ((i * 31 + seed) % 26) as u8))
            .collect()
    }

    async fn pings(remote: &echo::Client, sizes: &[usize]) -> Vec<String> {
        let calls = sizes.iter().enumerate().map(|(seed, &len)| {
            let mut request = remote.ping_request();
            request.get().set_msg(text(len, seed));
            async move {
                let reply = request.send().promise.await.expect("call failed");
                reply.get().unwrap().get_reply().unwrap().to_string().unwrap()
            }
        });
        futures::future::join_all(calls).await
    }

    fn sizes() -> impl Strategy<Value = Vec<usize>> {
        prop::collection::vec(
            prop_oneof![0usize..64, 3000usize..6000, 100_000usize..500_000],
            1..12,
        )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        #[test]
        fn stock_twoparty_and_this_network_understand_each_other(
            sizes in sizes(),
            ours_is_server in any::<bool>(),
        ) {
            let expected: Vec<String> = sizes
                .iter()
                .enumerate()
                .map(|(seed, &len)| text(len, seed))
                .collect();
            let (ours_down, ours_up) = compio::runtime::Runtime::new().unwrap().block_on(async {
                let (server_conn, client_conn) = uds_pair().await;
                let (our_conn, our_side, stock_conn, stock_side) = if ours_is_server {
                    (server_conn, Side::Server, client_conn, Side::Client)
                } else {
                    (client_conn, Side::Client, server_conn, Side::Server)
                };
                let ours = spawn_session::<echo::Client, _>(our_conn, our_side, Mirror);
                let theirs = stock(stock_conn, stock_side);
                futures::join!(pings(ours.remote(), &sizes), pings(&theirs, &sizes))
            });
            prop_assert_eq!(&ours_down, &expected);
            prop_assert_eq!(&ours_up, &expected);
        }
    }
}
