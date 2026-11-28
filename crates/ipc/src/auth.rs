use std::fmt;
use std::io;
use std::time::Duration;

use hmac::{Hmac, Mac};
use rand::RngExt;
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::Connection;

pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

pub const TOKEN_LEN: usize = 32;
const NONCE_LEN: usize = 16;
const PROOF_LEN: usize = 32;
const LABEL: &[u8] = b"concord-ipc/1";

type Proof = [u8; PROOF_LEN];

/// The shared secret of one host session: 32 lowercase hex digits, the 128-bit
/// session ID the host generated. It is never written to a connection, only
/// keyed into the proofs, and has no `Display`.
#[derive(Clone)]
pub struct Token(Box<[u8]>);

impl Token {
    pub fn parse(text: &str) -> Result<Self, AuthError> {
        let valid = text.len() == TOKEN_LEN
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !valid {
            return Err(AuthError::BadToken);
        }
        Ok(Token(text.as_bytes().into()))
    }

    fn mac(&self) -> Hmac<Sha256> {
        #[allow(clippy::expect_used, reason = "HMAC accepts a key of any length")]
        Hmac::new_from_slice(&self.0).expect("HMAC accepts a key of any length")
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(..)")
    }
}

#[derive(Debug)]
pub enum AuthError {
    BadToken,
    Timeout,
    Io(io::Error),
    Malformed,
    Rejected,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::BadToken => f.write_str("the session token is not 32 hex digits"),
            AuthError::Timeout => f.write_str("the peer did not answer in time"),
            AuthError::Io(err) => write!(f, "the connection failed: {err}"),
            AuthError::Malformed => f.write_str("the peer sent something that is not a handshake"),
            AuthError::Rejected => f.write_str("the peer does not know the session token"),
        }
    }
}

impl std::error::Error for AuthError {}

impl From<io::Error> for AuthError {
    fn from(err: io::Error) -> Self {
        AuthError::Io(err)
    }
}

#[derive(Clone, Copy)]
enum Role {
    Initiator,
    Responder,
}

impl Role {
    fn byte(self) -> u8 {
        match self {
            Role::Initiator => 1,
            Role::Responder => 2,
        }
    }
}

fn keyed(token: &Token, role: Role, initiator: &[u8], responder: &[u8]) -> Hmac<Sha256> {
    let mut mac = token.mac();
    mac.update(LABEL);
    mac.update(&[role.byte()]);
    mac.update(initiator);
    mac.update(responder);
    mac
}

fn proof(token: &Token, role: Role, initiator: &[u8], responder: &[u8]) -> Proof {
    keyed(token, role, initiator, responder)
        .finalize()
        .into_bytes()
        .into()
}

fn verify(
    token: &Token,
    role: Role,
    initiator: &[u8],
    responder: &[u8],
    claimed: &[u8],
) -> Result<(), AuthError> {
    keyed(token, role, initiator, responder)
        .verify_slice(claimed)
        .map_err(|_| AuthError::Rejected)
}

fn nonce() -> [u8; NONCE_LEN] {
    rand::rng().random()
}

async fn send<C: Connection>(io: &mut C, body: &[u8]) -> Result<(), AuthError> {
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(body);
    io.write_all(&frame).await?;
    io.flush().await?;
    Ok(())
}

async fn receive<C: Connection>(io: &mut C, len: usize) -> Result<Vec<u8>, AuthError> {
    let mut header = [0u8; 4];
    io.read_exact(&mut header).await?;
    if u32::from_le_bytes(header) as usize != len {
        return Err(AuthError::Malformed);
    }
    let mut body = vec![0u8; len];
    io.read_exact(&mut body).await?;
    Ok(body)
}

async fn within<T>(
    work: impl std::future::Future<Output = Result<T, AuthError>>,
) -> Result<T, AuthError> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, work)
        .await
        .map_err(|_| AuthError::Timeout)?
}

/// The side that dialled. It speaks first with a nonce and sends its own proof
/// only after the responder's has checked out, so a listener that does not
/// know the token learns nothing but a random number.
pub async fn initiate<C: Connection>(io: &mut C, token: &Token) -> Result<(), AuthError> {
    within(async {
        let ours = nonce();
        send(io, &ours).await?;
        let reply = receive(io, NONCE_LEN + PROOF_LEN).await?;
        let (theirs, claimed) = reply.split_at(NONCE_LEN);
        verify(token, Role::Responder, &ours, theirs, claimed)?;
        send(io, &proof(token, Role::Initiator, &ours, theirs)).await
    })
    .await
}

/// The side that listened. The initiator's proof is the last thing it reads,
/// so the connection carries no RPC before both sides have been verified.
pub async fn respond<C: Connection>(io: &mut C, token: &Token) -> Result<(), AuthError> {
    within(async {
        let theirs = receive(io, NONCE_LEN).await?;
        let ours = nonce();
        let mut reply = ours.to_vec();
        reply.extend_from_slice(&proof(token, Role::Responder, &theirs, &ours));
        send(io, &reply).await?;
        let claimed = receive(io, PROOF_LEN).await?;
        verify(token, Role::Initiator, &theirs, &ours, &claimed)
    })
    .await
}

#[cfg(test)]
mod tests;
