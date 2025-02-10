use crate::handshake::envelope::{parse_envelope, Envelope};
use futures::{AsyncReadExt, AsyncWriteExt};
use libp2p::futures::{AsyncRead, AsyncWrite};
use libp2p::request_response::Codec as RequestResponseCodec;
use std::io;
use async_trait::async_trait;
use libp2p::StreamProtocol;
use tracing::debug;
use crate::handshake::envelope;

impl From<envelope::Error> for io::Error {
    fn from(err: envelope::Error) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, err)
    }
}

/// A `Codec` that reads/writes an **`Envelope`**
#[derive(Clone, Debug, Default)]
pub struct Codec;

#[async_trait]
impl RequestResponseCodec for Codec {
    type Protocol = StreamProtocol;
    type Request = Envelope;
    type Response = Envelope;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        debug!("reading handsake request");
        let mut msg_buf = Vec::new();
        let num_bytes_read = io.read_to_end(&mut msg_buf).await?;
        debug!(?num_bytes_read, "read handshake request");
        let env = Envelope::decode_from_slice(&msg_buf)?;
        debug!(?env, "decoded handshake request");
        Ok(env)
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        debug!("reading handshake response");
        let mut msg_buf = Vec::new();
        // We don't need a varint here because we always read only one message in protocol.
        // In this way we can just read until the end of the stream.
        let num_bytes_read = io.read_to_end(&mut msg_buf).await?;
        debug!(?num_bytes_read, "read handshake response");

        let env = parse_envelope(&msg_buf)?;

        debug!(?env, "decoded handshake response");
        Ok(env)
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        debug!(req = ?req, "writing handshake request");
        let raw = req.encode_to_vec()?;
        io.write_all(&raw).await?;
        io.close().await?;
        debug!("wrote handshake request");
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        debug!("writing handshake response");
        let raw = res
            .encode_to_vec()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        io.write_all(&raw).await?;
        io.close().await?;
        debug!("wrote handshake response");
        Ok(())
    }
}
