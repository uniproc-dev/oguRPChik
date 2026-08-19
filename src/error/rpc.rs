use core::fmt;

use error_stack::Report;

const WIRE_PREFIX: &str = "[ogurpchik:";

#[derive(Debug)]
#[non_exhaustive]
pub enum RpcError {
    Setup,
    Remote {
        kind: RemoteErrorKind,
        code: Option<WireCode>,
    },
    Handler,
    Unimplemented,
    LimitExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RemoteErrorKind {
    Failed,
    Overloaded,
    Disconnected,
    Unimplemented,
    Other,
}

/// Machine-readable error code carried across the wire.
///
/// Attach one to a [`Report`] to opt that report into being matchable by the
/// peer: `Report::new(RpcError::Handler).attach(WireCode::PermissionDenied)`.
/// Without an attached code nothing structured crosses the wire, which is the
/// default — attachments otherwise stay local.
///
/// A code received from a peer is a *claim by that peer*, not a verified fact.
/// Branch on it for diagnostics and retry decisions; never for authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WireCode {
    Unauthenticated,
    PermissionDenied,
    InvalidArgument,
    NotFound,
    Unavailable,
    LimitExceeded,
    Internal,
    /// A code this build does not recognise — a peer running a newer version.
    Unknown,
}

impl WireCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unauthenticated => "unauthenticated",
            Self::PermissionDenied => "permission-denied",
            Self::InvalidArgument => "invalid-argument",
            Self::NotFound => "not-found",
            Self::Unavailable => "unavailable",
            Self::LimitExceeded => "limit-exceeded",
            Self::Internal => "internal",
            Self::Unknown => "unknown",
        }
    }

    pub fn from_slug(slug: &str) -> Self {
        match slug {
            "unauthenticated" => Self::Unauthenticated,
            "permission-denied" => Self::PermissionDenied,
            "invalid-argument" => Self::InvalidArgument,
            "not-found" => Self::NotFound,
            "unavailable" => Self::Unavailable,
            "limit-exceeded" => Self::LimitExceeded,
            "internal" => Self::Internal,
            _ => Self::Unknown,
        }
    }

    pub fn capnp_kind(self) -> capnp::ErrorKind {
        match self {
            Self::Unavailable => capnp::ErrorKind::Overloaded,
            _ => capnp::ErrorKind::Failed,
        }
    }

    /// Builds a coded exception directly, for handlers that return
    /// `capnp::Error` rather than a [`Report`].
    pub fn exception(self, message: impl fmt::Display) -> capnp::Error {
        capnp::Error {
            kind: self.capnp_kind(),
            extra: encode_wire_text(Some(self), &message.to_string()),
        }
    }
}

impl fmt::Display for WireCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A message deliberately reviewed as safe to disclose to the peer.
///
/// Attaching one replaces the context's `Display` output as the text sent over
/// the wire. Like [`WireCode`], this is opt-in: anything else attached to the
/// report stays local.
#[derive(Debug)]
pub struct WireMessage(pub String);

impl fmt::Display for WireMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Setup => f.write_str("failed to establish rpc connection"),
            Self::Remote {
                kind,
                code: Some(code),
            } => write!(f, "remote rpc error ({kind:?}, {code})"),
            Self::Remote { kind, code: None } => write!(f, "remote rpc error ({kind:?})"),
            Self::Handler => f.write_str("local handler failed"),
            Self::Unimplemented => f.write_str("method not implemented"),
            Self::LimitExceeded => f.write_str("message exceeded configured limits"),
        }
    }
}

impl core::error::Error for RpcError {}

/// The peer's own description of a remote failure, kept for local logs.
#[derive(Debug)]
pub struct RemoteMessage(pub String);

impl fmt::Display for RemoteMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn encode_wire_text(code: Option<WireCode>, message: &str) -> String {
    match code {
        Some(code) => format!("{WIRE_PREFIX}{}] {message}", code.as_str()),
        None => message.to_string(),
    }
}

fn decode_wire_text(extra: &str) -> (Option<WireCode>, &str) {
    let Some(rest) = extra.strip_prefix(WIRE_PREFIX) else {
        return (None, extra);
    };
    let Some(end) = rest.find(']') else {
        return (None, extra);
    };
    let message = rest[end + 1..].strip_prefix(' ').unwrap_or(&rest[end + 1..]);
    (Some(WireCode::from_slug(&rest[..end])), message)
}

pub fn from_capnp_exception(err: &capnp::Error) -> Report<RpcError> {
    let kind = match err.kind {
        capnp::ErrorKind::Failed => RemoteErrorKind::Failed,
        capnp::ErrorKind::Overloaded => RemoteErrorKind::Overloaded,
        capnp::ErrorKind::Disconnected => RemoteErrorKind::Disconnected,
        capnp::ErrorKind::Unimplemented => RemoteErrorKind::Unimplemented,
        _ => RemoteErrorKind::Other,
    };
    let (code, message) = decode_wire_text(&err.extra);
    Report::new(RpcError::Remote { kind, code }).attach(RemoteMessage(message.to_string()))
}

/// Projects a local report onto the wire.
///
/// Only what is explicitly opted in crosses: the context's `Display` output (or
/// an attached [`WireMessage`]) and an attached [`WireCode`]. Everything else
/// attached to the report — paths, PIDs, addresses — stays local, since the
/// peer may be an untrusted plugin.
///
/// A code received from elsewhere is not relayed automatically; a relaying peer
/// that wants to forward one attaches it deliberately.
pub fn to_capnp_exception<C>(report: &Report<C>) -> capnp::Error
where
    C: fmt::Display + Send + Sync + 'static,
{
    let code = report.downcast_ref::<WireCode>().copied();
    let message = match report.downcast_ref::<WireMessage>() {
        Some(message) => message.0.clone(),
        None => report.current_context().to_string(),
    };
    let extra = encode_wire_text(code, &message);

    let kind = match (code, report.downcast_ref::<RpcError>()) {
        (Some(code), _) => code.capnp_kind(),
        (None, Some(RpcError::Unimplemented)) => capnp::ErrorKind::Unimplemented,
        (None, Some(RpcError::Remote { .. })) => capnp::ErrorKind::Disconnected,
        _ => capnp::ErrorKind::Failed,
    };

    capnp::Error { kind, extra }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::TransportError;

    #[derive(Debug)]
    struct SensitivePath(std::path::PathBuf);

    impl fmt::Display for SensitivePath {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "socket path: {}", self.0.display())
        }
    }

    impl core::error::Error for SensitivePath {}

    #[test]
    fn layer_matching_survives_change_context() {
        let report = Report::new(TransportError::Connect)
            .attach("some local detail")
            .change_context(RpcError::Setup);

        assert!(matches!(report.current_context(), RpcError::Setup));
        assert!(report.contains::<TransportError>());
        assert!(matches!(
            report.downcast_ref::<TransportError>(),
            Some(TransportError::Connect)
        ));
    }

    #[test]
    fn outgoing_exception_never_carries_attachments() {
        let report = Report::new(SensitivePath(std::path::PathBuf::from(
            "/run/user/1000/very-secret-service.sock",
        )))
        .change_context(RpcError::Handler);

        let exception = to_capnp_exception(&report);

        assert_eq!(exception.kind, capnp::ErrorKind::Failed);
        assert!(!exception.extra.contains("secret"));
        assert!(!exception.extra.contains("/run/user"));
        assert_eq!(exception.extra, RpcError::Handler.to_string());
    }

    #[test]
    fn unimplemented_maps_to_capnp_unimplemented() {
        let report = Report::new(RpcError::Unimplemented);
        let exception = to_capnp_exception(&report);
        assert_eq!(exception.kind, capnp::ErrorKind::Unimplemented);
    }

    #[test]
    fn incoming_exception_roundtrip_preserves_kind_and_message() {
        let original = capnp::Error::disconnected("peer went away".to_string());
        let report = from_capnp_exception(&original);

        assert!(matches!(
            report.current_context(),
            RpcError::Remote {
                kind: RemoteErrorKind::Disconnected,
                code: None,
            }
        ));
        let msg = report.downcast_ref::<RemoteMessage>().unwrap();
        assert_eq!(msg.0, "peer went away");
    }

    #[test]
    fn remote_forwarded_as_disconnected_not_local_failure() {
        let incoming = from_capnp_exception(&capnp::Error::failed("upstream broke".to_string()));
        let outgoing = to_capnp_exception(&incoming);
        assert_eq!(outgoing.kind, capnp::ErrorKind::Disconnected);
    }

    #[test]
    fn attached_code_crosses_the_wire_and_is_matchable() {
        let report = Report::new(SensitivePath(std::path::PathBuf::from("/run/user/1000/x")))
            .change_context(RpcError::Handler)
            .attach(WireCode::PermissionDenied);

        let exception = to_capnp_exception(&report);
        assert!(!exception.extra.contains("/run/user"));

        let received = from_capnp_exception(&exception);
        assert!(matches!(
            received.current_context(),
            RpcError::Remote {
                code: Some(WireCode::PermissionDenied),
                ..
            }
        ));
    }

    #[test]
    fn wire_message_replaces_context_text_but_not_attachments() {
        let report = Report::new(SensitivePath(std::path::PathBuf::from("/run/user/1000/x")))
            .change_context(RpcError::Handler)
            .attach(WireCode::NotFound)
            .attach(WireMessage("no such plugin: metrics".to_string()));

        let exception = to_capnp_exception(&report);
        assert!(!exception.extra.contains("/run/user"));

        let received = from_capnp_exception(&exception);
        assert_eq!(
            received.downcast_ref::<RemoteMessage>().unwrap().0,
            "no such plugin: metrics"
        );
    }

    #[test]
    fn unavailable_maps_to_overloaded_so_peers_know_to_retry() {
        let report = Report::new(RpcError::Handler).attach(WireCode::Unavailable);
        let exception = to_capnp_exception(&report);
        assert_eq!(exception.kind, capnp::ErrorKind::Overloaded);
    }

    #[test]
    fn unrecognised_code_degrades_to_unknown_not_an_error() {
        let from_newer_peer = capnp::Error::failed("[ogurpchik:quota-exhausted] slow down".into());
        let received = from_capnp_exception(&from_newer_peer);

        assert!(matches!(
            received.current_context(),
            RpcError::Remote {
                code: Some(WireCode::Unknown),
                ..
            }
        ));
        assert_eq!(
            received.downcast_ref::<RemoteMessage>().unwrap().0,
            "slow down"
        );
    }

    #[test]
    fn malformed_prefix_is_treated_as_plain_text() {
        for extra in ["[ogurpchik:unterminated", "[ogurpchik", "plain message"] {
            let received = from_capnp_exception(&capnp::Error::failed(extra.to_string()));
            assert!(matches!(
                received.current_context(),
                RpcError::Remote { code: None, .. }
            ));
            assert_eq!(received.downcast_ref::<RemoteMessage>().unwrap().0, extra);
        }
    }

    #[test]
    fn handler_built_exception_is_matchable_by_the_caller() {
        let exception = WireCode::InvalidArgument.exception("port must be non-zero");
        let received = from_capnp_exception(&exception);

        assert!(matches!(
            received.current_context(),
            RpcError::Remote {
                code: Some(WireCode::InvalidArgument),
                ..
            }
        ));
        assert_eq!(
            received.downcast_ref::<RemoteMessage>().unwrap().0,
            "port must be non-zero"
        );
    }

    #[test]
    fn relayed_remote_code_is_not_re_emitted_without_intent() {
        let incoming =
            from_capnp_exception(&WireCode::PermissionDenied.exception("plugin said no"));
        let relayed = to_capnp_exception(&incoming);

        let (code, _) = decode_wire_text(&relayed.extra);
        assert_eq!(code, None);
    }
}
