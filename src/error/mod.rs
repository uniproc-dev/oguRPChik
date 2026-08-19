
mod endpoint;
mod handshake;
mod rpc;
mod transport;

pub use endpoint::EndpointError;
pub use handshake::HandshakeError;
pub use rpc::{
    RemoteErrorKind, RemoteMessage, RpcError, WireCode, WireMessage, from_capnp_exception,
    to_capnp_exception,
};
pub use transport::TransportError;

pub type Result<T, C> = core::result::Result<T, error_stack::Report<C>>;
