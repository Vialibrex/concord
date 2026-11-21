use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use concord_common::{
    Address, BoxStream, CoreError, DialCx, Outbound, OutboundInfo, OutboundKind, PacketSession,
};
use concord_config::proxy::{HttpProxyOpts, ProxyDef};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::ctx::{BuildCtx, BuildError};
use crate::link::simple_link;
use crate::node::{Link, info_for};

const MAX_HEAD: usize = 10 << 20;

fn fail(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

pub(crate) async fn connect_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    target: &Address,
    auth: Option<(&str, &str)>,
    extra: &[(String, String)],
) -> io::Result<()> {
    let authority = target.to_string();
    let mut headers: Vec<(String, String)> = vec![
        ("Host".into(), authority.clone()),
        ("User-Agent".into(), "Go-http-client/1.1".into()),
        ("Proxy-Connection".into(), "Keep-Alive".into()),
    ];
    let mut set = |key: &str, value: String| match headers.iter_mut().find(|(k, _)| k == key) {
        Some(slot) => slot.1 = value,
        None => headers.push((key.to_string(), value)),
    };
    for (key, value) in extra {
        set(key, value.clone());
    }
    if let Some((user, pass)) = auth {
        let token = STANDARD.encode(format!("{user}:{pass}"));
        set("Proxy-Authorization", format!("Basic {token}"));
    }
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\n");
    for (key, value) in &headers {
        request.push_str(key);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    io.write_all(request.as_bytes()).await?;
    io.flush().await?;

    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && !head.ends_with(b"\n\n") {
        if head.len() >= MAX_HEAD {
            return Err(fail("http proxy response header too large"));
        }
        io.read_exact(&mut byte).await?;
        head.push(byte[0]);
    }
    let line = head
        .split(|b| *b == b'\n')
        .next()
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    let mut parts = line.trim_end().splitn(3, ' ');
    let _version = parts.next();
    let code: u16 = parts
        .next()
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| fail("malformed HTTP response"))?;
    match code {
        200 => Ok(()),
        407 => Err(fail("HTTP need auth")),
        405 => Err(fail("CONNECT method not allowed by proxy")),
        500.. => Err(CoreError::TargetRefused(line.trim_end().to_string()).into()),
        other => Err(
            CoreError::TargetRefused(format!("can not connect remote err code: {other}")).into(),
        ),
    }
}

struct HttpProxy {
    info: OutboundInfo,
    link: Link,
    auth: Option<(String, String)>,
    headers: Vec<(String, String)>,
}

#[async_trait]
impl Outbound for HttpProxy {
    fn info(&self) -> &OutboundInfo {
        &self.info
    }

    async fn connect(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        let mut stream = self.link.open(cx).await?;
        let auth = self.auth.as_ref().map(|(u, p)| (u.as_str(), p.as_str()));
        connect_handshake(&mut stream, dst, auth, &self.headers).await?;
        Ok(stream)
    }

    async fn associate(
        &self,
        _cx: &DialCx<'_>,
        _hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        Err(CoreError::UdpUnsupported(self.info.name.to_string()).into())
    }
}

pub(crate) fn build(
    def: &ProxyDef,
    opts: &HttpProxyOpts,
    ctx: &BuildCtx,
) -> Result<Arc<dyn Outbound>, BuildError> {
    let link = simple_link(def, &opts.server, opts.port, &opts.tls, ctx)?;
    let auth = (!opts.username.is_empty() && !opts.password.is_empty())
        .then(|| (opts.username.clone(), opts.password.clone()));
    Ok(Arc::new(HttpProxy {
        info: info_for(def, OutboundKind::Http, &opts.server, opts.port, false),
        link,
        auth,
        headers: opts
            .headers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    }))
}

#[cfg(test)]
mod tests {
    use tokio::io::duplex;

    use super::*;

    async fn serve(status: &str) -> (tokio::io::DuplexStream, tokio::task::JoinHandle<String>) {
        let (near, mut far) = duplex(4096);
        let status = status.to_string();
        let task = tokio::spawn(async move {
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                far.read_exact(&mut byte).await.unwrap();
                head.push(byte[0]);
            }
            far.write_all(format!("HTTP/1.1 {status}\r\n\r\ntunnel").as_bytes())
                .await
                .unwrap();
            String::from_utf8(head).unwrap()
        });
        (near, task)
    }

    #[tokio::test]
    async fn connect_sends_auth_and_extra_headers() {
        let (mut near, task) = serve("200 Connection established").await;
        let extra = vec![
            ("X-Extra".to_string(), "1".to_string()),
            ("User-Agent".into(), "ua".into()),
        ];
        connect_handshake(
            &mut near,
            &Address::new("example.com", 443),
            Some(("u", "p")),
            &extra,
        )
        .await
        .unwrap();
        let request = task.await.unwrap();
        assert!(request.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
        assert!(request.contains("Host: example.com:443\r\n"));
        assert!(request.contains("User-Agent: ua\r\n"));
        assert!(request.contains("X-Extra: 1\r\n"));
        assert!(request.contains("Proxy-Authorization: Basic dTpw\r\n"));
        let mut rest = [0u8; 6];
        near.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"tunnel");
    }

    #[tokio::test]
    async fn error_statuses_map_to_messages() {
        for (status, expect) in [
            ("407 Proxy Authentication Required", "HTTP need auth"),
            ("405 Method Not Allowed", "not allowed"),
            ("502 Bad Gateway", "502 Bad Gateway"),
            ("403 Forbidden", "err code: 403"),
        ] {
            let (mut near, _task) = serve(status).await;
            let err = connect_handshake(&mut near, &Address::new("a.test", 1), None, &[])
                .await
                .unwrap_err();
            assert!(err.to_string().contains(expect), "{status}: {err}");
        }
    }

    #[tokio::test]
    async fn only_the_targets_refusals_are_typed() {
        for (status, typed) in [
            ("407 Proxy Authentication Required", false),
            ("405 Method Not Allowed", false),
            ("502 Bad Gateway", true),
            ("403 Forbidden", true),
        ] {
            let (mut near, _task) = serve(status).await;
            let err = connect_handshake(&mut near, &Address::new("a.test", 1), None, &[])
                .await
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::Other, "{status}");
            assert_eq!(
                matches!(CoreError::of(&err), Some(CoreError::TargetRefused(_))),
                typed,
                "{status}"
            );
        }
        let (mut near, _task) = serve("502 Bad Gateway").await;
        let err = connect_handshake(&mut near, &Address::new("a.test", 1), None, &[])
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "HTTP/1.1 502 Bad Gateway");
    }

    #[test]
    fn ipv6_targets_are_bracketed() {
        assert_eq!(Address::new("::1", 80).to_string(), "[::1]:80");
    }
}
