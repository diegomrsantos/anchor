use crate::handshake::envelope::{parse_envelope, Envelope};
use futures::{AsyncReadExt, AsyncWriteExt};
use libp2p::futures::{AsyncRead, AsyncWrite};
use libp2p::request_response::Codec;
use std::io;
use async_trait::async_trait;
use libp2p::StreamProtocol;
use prost::bytes::BytesMut;
use prost::encoding::{decode_varint, encode_varint, encoded_len_varint};
use prost::Message;
use tracing::debug;
use crate::handshake::types::NodeInfo;

/// A `Codec` that reads/writes an **`Envelope`**
#[derive(Clone, Debug, Default)]
pub struct EnvelopeCodec;

#[async_trait]
impl Codec for EnvelopeCodec {
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
        let env = Envelope::decode_from_slice(&msg_buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
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
        let num_bytes_read = io.read_to_end(&mut msg_buf).await?;
        debug!(?num_bytes_read, "read handshake response");

        let env = parse_envelope(&msg_buf).unwrap();

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
