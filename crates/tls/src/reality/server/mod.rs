//! A REALITY server's handshake steps, after metacubex/utls `v1.9.0-alpha.1` `reality.go`.

mod auth;
mod cert;
mod flight;
mod hello;
mod share;
#[cfg(test)]
mod testing;

pub(crate) use auth::RealityAuth;
pub(crate) use cert::RealityCert;
pub(crate) use flight::ServerFlight;
pub(crate) use hello::ClientHello;
pub(crate) use share::server_share;
