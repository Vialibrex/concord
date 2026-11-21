use std::io;

/// Failures a caller reacts to rather than just reports. They travel inside an
/// `io::Error`, so the layers of `connect` keep one error type.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CoreError {
    #[error("reject loopback connection to {0}")]
    Loopback(String),
    #[error("dialer proxy loop through {0}")]
    DialerLoop(String),
    #[error("proxy {0} not found")]
    UnknownNode(String),
    #[error("proxy {0} is not supported by this core")]
    QuarantinedNode(String),
    #[error("the process is out of file descriptors")]
    FdPressure,
    #[error("no IP found for {0}")]
    IpNotFound(String),
    #[error("IPv6 is disabled")]
    Ipv6Disabled,
    #[error("connection rejected by {0}")]
    Rejected(String),
    #[error("{0} does not support UDP")]
    UdpUnsupported(String),
    /// The node answered, and its answer says the target refused or could not be reached.
    #[error("{0}")]
    TargetRefused(String),
}

impl CoreError {
    pub fn of(err: &io::Error) -> Option<&CoreError> {
        err.get_ref()?.downcast_ref()
    }
}

impl From<CoreError> for io::Error {
    fn from(err: CoreError) -> Self {
        let kind = match err {
            CoreError::Rejected(_) | CoreError::Loopback(_) => io::ErrorKind::ConnectionRefused,
            CoreError::UdpUnsupported(_) => io::ErrorKind::Unsupported,
            _ => io::ErrorKind::Other,
        };
        io::Error::new(kind, err)
    }
}

pub fn io_error(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

/// These come from the target, not from the path to it, so a retry cannot help.
pub fn no_retry(err: &io::Error) -> bool {
    matches!(
        CoreError::of(err),
        Some(
            CoreError::Loopback(_)
                | CoreError::IpNotFound(_)
                | CoreError::Ipv6Disabled
                | CoreError::Rejected(_)
                | CoreError::QuarantinedNode(_)
                | CoreError::DialerLoop(_)
                | CoreError::UnknownNode(_)
                | CoreError::UdpUnsupported(_)
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_core_error_survives_the_io_error() {
        let err: io::Error = CoreError::Loopback("1.1.1.1:80".into()).into();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
        assert!(no_retry(&err));
        assert!(!no_retry(&io::Error::from(io::ErrorKind::TimedOut)));
    }

    #[test]
    fn a_target_refusal_keeps_its_text_and_may_be_retried() {
        let err: io::Error = CoreError::TargetRefused("remote said no".into()).into();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert_eq!(err.to_string(), "remote said no");
        assert!(matches!(
            CoreError::of(&err),
            Some(CoreError::TargetRefused(_))
        ));
        assert!(!no_retry(&err));
    }
}
