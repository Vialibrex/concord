mod cert;
mod handshake;
mod hello;
pub(crate) mod schedule;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        unused_imports,
        reason = "the REALITY listener takes it in a later commit"
    )
)]
pub(crate) mod server;
mod spider;
mod stream;
mod wire;

pub(crate) use handshake::RealityClient;
pub use handshake::SessionIdSealer;
#[cfg(test)]
pub(crate) use hello::{HelloParams, build_client_hello};
#[cfg(test)]
pub(crate) use schedule::{CT_APPLICATION_DATA, CT_HANDSHAKE, RecordKey, Suite};
pub use stream::RealityStream;
#[cfg(test)]
pub(crate) use wire::put_u24;
