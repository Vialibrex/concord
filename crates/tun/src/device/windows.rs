use super::*;

/// tun-rs answers from wintun's rings without drawing on Tokio's cooperative budget
/// (`vendor/tun-rs/src/async_device/windows/mod.rs`, `poll_recv`, `poll_send`), on which the
/// driver ends a busy pass; each call draws one unit, as Tokio's own I/O does.
impl Device for TunDevice {
    fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let budget = ready!(tokio::task::coop::poll_proceed(cx));
        let read = ready!(self.inner.poll_recv(cx, buf));
        budget.made_progress();
        Poll::Ready(read)
    }

    fn poll_send(&self, cx: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<usize>> {
        let budget = ready!(tokio::task::coop::poll_proceed(cx));
        let sent = ready!(self.inner.poll_send(cx, packet));
        budget.made_progress();
        Poll::Ready(sent)
    }
}

/// The interface resolves through the DNS hijack address only with `auto-route`, as in sing-tun.
pub(super) fn set_windows_dns(
    device: &tun_rs::AsyncDevice,
    options: &TunOptions,
) -> io::Result<()> {
    for (addresses, is_v4) in [
        (&options.inet4_address, true),
        (&options.inet6_address, false),
    ] {
        let Some(first) = addresses.first() else {
            continue;
        };
        match first.next_host().filter(|_| options.auto_route) {
            Some(server) => device.set_dns_servers(&[server])?,
            None => device.clear_dns_servers(is_v4)?,
        }
    }
    Ok(())
}

pub(super) fn wintun_path(options: &TunOptions) -> io::Result<String> {
    let path = match &options.wintun_path {
        Some(path) => path.clone(),
        None => crate::wintun::install()?,
    };
    Ok(path.to_string_lossy().into_owned())
}
