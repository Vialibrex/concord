use std::io;

use aws_lc_rs::constant_time::verify_slices_are_equal;

use super::super::handshake::{
    HS_CERTIFICATE, HS_CERTIFICATE_VERIFY, HS_ENCRYPTED_EXTENSIONS, HS_FINISHED, SCHEME_ED25519,
    certificate_verify_message,
};
use super::super::hello::put_len16;
use super::super::schedule::{
    HandshakeSecrets, Hash, RecordKey, Suite, application_secrets, finished_verify_data,
    handshake_secrets,
};
use super::super::wire::put_u24;
use super::cert::RealityCert;
use crate::error::invalid_data;

/// Go's `sendServerParameters`, `sendServerCertificate`, `sendServerFinished`
/// (`reality.go:286-294`) and `readClientFinished` (`reality.go:552`).
pub(crate) struct ServerFlight {
    suite: Suite,
    hash: Hash,
    secrets: HandshakeSecrets,
    transcript: Vec<u8>,
}

/// The flight is out; only the client's Finished is left.
pub(crate) struct AwaitingFinished(ServerFlight);

pub(crate) struct TrafficSecrets {
    pub(crate) client: Vec<u8>,
    pub(crate) server: Vec<u8>,
}

impl ServerFlight {
    pub(crate) fn new(
        suite: Suite,
        shared: &[u8],
        client_hello: &[u8],
        server_hello: &[u8],
    ) -> Self {
        let mut transcript = client_hello.to_vec();
        transcript.extend_from_slice(server_hello);
        let hash = suite.hash();
        let secrets = handshake_secrets(hash, shared, &transcript);
        ServerFlight {
            suite,
            hash,
            secrets,
            transcript,
        }
    }

    pub(crate) fn server_key(&self) -> io::Result<RecordKey> {
        RecordKey::new(self.suite, &self.secrets.server)
    }

    pub(crate) fn client_key(&self) -> io::Result<RecordKey> {
        RecordKey::new(self.suite, &self.secrets.client)
    }

    /// EncryptedExtensions, Certificate, CertificateVerify and Finished, in the order they
    /// go out.
    pub(crate) fn messages(
        mut self,
        extensions: &[u8],
        der: &[u8],
        cert: &RealityCert,
    ) -> io::Result<([Vec<u8>; 4], AwaitingFinished)> {
        let mut body = Vec::with_capacity(extensions.len() + 2);
        put_len16(&mut body, extensions.len())?;
        body.extend_from_slice(extensions);
        let encrypted_extensions = self.message(HS_ENCRYPTED_EXTENSIONS, &body);
        let mut entries = Vec::with_capacity(der.len() + 5);
        put_u24(&mut entries, der.len());
        entries.extend_from_slice(der);
        entries.extend_from_slice(&[0, 0]);
        let mut body = vec![0];
        put_u24(&mut body, entries.len());
        body.extend_from_slice(&entries);
        let certificate = self.message(HS_CERTIFICATE, &body);
        let signature = cert.sign(&certificate_verify_message(
            &self.hash.digest(&self.transcript),
        ));
        let mut body = SCHEME_ED25519.to_be_bytes().to_vec();
        put_len16(&mut body, signature.len())?;
        body.extend_from_slice(&signature);
        let verify = self.message(HS_CERTIFICATE_VERIFY, &body);
        let verify_data = finished_verify_data(self.hash, &self.secrets.server, &self.transcript);
        let finished = self.message(HS_FINISHED, &verify_data);
        Ok((
            [encrypted_extensions, certificate, verify, finished],
            AwaitingFinished(self),
        ))
    }

    fn message(&mut self, kind: u8, body: &[u8]) -> Vec<u8> {
        let mut message = vec![kind];
        put_u24(&mut message, body.len());
        message.extend_from_slice(body);
        self.transcript.extend_from_slice(&message);
        message
    }
}

impl AwaitingFinished {
    pub(crate) fn client_finished(self, message: &[u8]) -> io::Result<TrafficSecrets> {
        let ServerFlight {
            hash,
            secrets,
            transcript,
            ..
        } = self.0;
        let expected = finished_verify_data(hash, &secrets.client, &transcript);
        let mut wanted = vec![HS_FINISHED];
        put_u24(&mut wanted, expected.len());
        wanted.extend_from_slice(&expected);
        verify_slices_are_equal(&wanted, message)
            .map_err(|_| invalid_data("REALITY: client Finished does not verify"))?;
        let (client, server) = application_secrets(hash, &secrets.master, &transcript);
        Ok(TrafficSecrets { client, server })
    }
}
