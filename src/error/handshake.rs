use core::fmt;

#[derive(Debug)]
#[non_exhaustive]
pub enum HandshakeError {
    UnsupportedVersion,
    SchemeMismatch,
    SchemaMismatch,
    InvalidProof,
    Rejected,
    Timeout,
    MalformedPacket,
    PeerAttestationUnavailable,
    SignedProcessVerificationFailed,
    ConnectionLimitReached,
    Io,
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion => f.write_str("unsupported handshake version"),
            Self::SchemeMismatch => f.write_str("handshake auth scheme mismatch"),
            Self::SchemaMismatch => f.write_str("application schema mismatch"),
            Self::InvalidProof => f.write_str("invalid handshake proof"),
            Self::Rejected => f.write_str("handshake rejected by peer"),
            Self::Timeout => f.write_str("handshake timed out"),
            Self::MalformedPacket => f.write_str("malformed handshake packet"),
            Self::PeerAttestationUnavailable => f.write_str(
                "signed-process auth requires a transport that can attest the peer's identity",
            ),
            Self::SignedProcessVerificationFailed => {
                f.write_str("signed-process verification failed")
            }
            Self::ConnectionLimitReached => {
                f.write_str("connection rejected: server is in one-to-one mode")
            }
            Self::Io => f.write_str("i/o failure during handshake"),
        }
    }
}

impl core::error::Error for HandshakeError {}
