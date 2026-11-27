mod frame;

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use concord_common::sync::lock;
use concord_common::{BoxStream, Tasks};
use h2::client::SendRequest;
use http::{Method, Request, Uri};

use crate::DialFn;
use crate::h2io::{Activity, ClientSlot, H2Body, Incoming, StreamGuard, h2_io_error};
pub(crate) use frame::gun_framed;

const DEFAULT_SERVICE: &str = "GunService";
const DEFAULT_USER_AGENT: &str = "grpc-go/1.36.0";
const MAX_HEADER_LIST_SIZE: u32 = 10 << 20;

fn client_builder() -> h2::client::Builder {
    let mut builder = crate::h2io::client_builder();
    builder.max_header_list_size(MAX_HEADER_LIST_SIZE);
    builder
}

#[derive(Clone, Debug, Default)]
pub struct GrpcOptions {
    pub service_name: String,
    pub user_agent: String,
    /// The request's `:authority`: `servername`, or the node's `host:port` when none is set.
    pub authority: String,
    /// Seconds, 0 for no health check.
    pub ping_interval: u32,
    pub max_connections: usize,
    pub min_streams: usize,
    pub max_streams: usize,
}

pub fn service_path(service_name: &str) -> String {
    let name = if service_name.is_empty() {
        DEFAULT_SERVICE
    } else {
        service_name
    };
    if name.starts_with('/') {
        name.to_string()
    } else {
        format!("/{name}/Tun")
    }
}

/// One node's gun client. Streams share a pool of HTTP/2 connections the way
/// `gun.Client` shares non-strict `http.Transport`s: `max_connections`,
/// `min_streams`, and `max_streams` balance across connections that still have
/// capacity under the peer's advertised stream limit, and once every pooled
/// connection is full another connection opens.
pub struct GunClient {
    opts: GrpcOptions,
    dial: DialFn,
    pool: Mutex<Vec<Arc<ClientSlot>>>,
    tasks: Tasks,
}

impl GunClient {
    /// `dial` returns a stream ready for HTTP/2: TCP, then TLS offering `h2` when the
    /// node uses TLS. Reuse `tls_dial` for the TLS case.
    pub fn new(opts: GrpcOptions, dial: DialFn, tasks: Tasks) -> Arc<GunClient> {
        Arc::new(GunClient {
            opts,
            dial,
            pool: Mutex::new(Vec::new()),
            tasks,
        })
    }

    fn default_pool(&self) -> bool {
        self.opts.max_connections == 0 && self.opts.min_streams == 0 && self.opts.max_streams == 0
    }

    fn pick(&self) -> (Arc<ClientSlot>, StreamGuard) {
        let mut pool = lock(&self.pool);
        pool.retain(|slot| !slot.is_dead());
        let available = pool
            .iter()
            .filter(|slot| slot.has_capacity())
            .min_by_key(|slot| slot.streams())
            .cloned();
        let reuse = available.filter(|slot| {
            let streams = slot.streams();
            if streams == 0 || self.default_pool() {
                return true;
            }
            if self.opts.max_connections > 0 {
                pool.len() >= self.opts.max_connections || streams < self.opts.min_streams
            } else {
                self.opts.max_streams > 0 && streams < self.opts.max_streams
            }
        });
        let slot = reuse.unwrap_or_else(|| {
            let fresh = Arc::new(ClientSlot::new());
            pool.push(fresh.clone());
            fresh
        });
        let guard = slot.reserve();
        (slot, guard)
    }

    async fn sender(&self, slot: &ClientSlot) -> io::Result<(SendRequest<Bytes>, Arc<Activity>)> {
        let interval = Duration::from_secs(u64::from(self.opts.ping_interval));
        slot.ready_sender(&self.dial, &client_builder(), &self.tasks, Some(interval))
            .await
    }

    pub async fn dial(&self) -> io::Result<BoxStream> {
        let (slot, guard) = self.pick();
        let (mut sender, activity) = self.sender(&slot).await?;
        let user_agent = if self.opts.user_agent.is_empty() {
            DEFAULT_USER_AGENT
        } else {
            &self.opts.user_agent
        };
        let uri = Uri::builder()
            .scheme("https")
            .authority(self.opts.authority.as_str())
            .path_and_query(service_path(&self.opts.service_name))
            .build()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
        let request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/grpc")
            .header("user-agent", user_agent)
            .body(())
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
        let (response, send) = sender.send_request(request, false).map_err(h2_io_error)?;
        let body = H2Body::new(send, Incoming::Response(response))
            .with_activity(activity)
            .on_drop(move || drop(guard));
        Ok(gun_framed(body))
    }
}

#[cfg(test)]
mod tests;
