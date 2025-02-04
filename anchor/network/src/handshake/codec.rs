use crate::handshake::record::envelope::Envelope;
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


/// Reads a varint‑encoded length from the async stream using the Prost decoder.
/// We read one byte at a time (maximum 10 bytes) until we see a byte with its
/// high‐bit clear. Then we call Prost’s `decode_varint` on the accumulated slice.
async fn read_varint_length<T: AsyncRead + Unpin>(io: &mut T) -> io::Result<usize> {
    // A varint is at most 10 bytes long.
    let mut buf = [0u8; 10];
    let mut pos = 0;
    loop {
        if pos >= buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "varint too long",
            ));
        }
        // Read one byte.
        io.read_exact(&mut buf[pos..pos + 1]).await?;
        // If the high-bit is clear, we have reached the end of the varint.
        if buf[pos] & 0x80 == 0 {
            // Create a slice containing the varint bytes.
            let mut slice = &buf[..pos + 1];
            // Use Prost’s varint decoder.
            let value = decode_varint(&mut slice)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            return Ok(value as usize);
        }
        pos += 1;
    }
}

/// Writes the given length as a varint‑encoded prefix to the async stream,
/// using Prost’s `encode_varint` function.
async fn write_varint_length<T: AsyncWrite + Unpin>(io: &mut T, value: usize) -> io::Result<()> {
    let cap = encoded_len_varint(value as u64);
    let mut buf = BytesMut::with_capacity(cap);
    encode_varint(value as u64, &mut buf);
    io.write_all(&buf).await?;
    Ok(())
}

/// A `Codec` that reads/writes an **`Envelope`** in a length-prefixed Protobuf style:
///  - <4-byte big-endian length><protobuf message>
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
        // read length
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let msg_len = u32::from_be_bytes(len_buf) as usize;

        // read that many bytes
        let mut msg_buf = vec![0u8; msg_len];
        io.read_exact(&mut msg_buf).await?;

        // decode
        let env = Envelope::decode_from_slice(&msg_buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        debug!("read handshake request");
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
        // debug!("reading handshake response");
        // // same approach
        // let mut len_buf = [0u8; 4];
        // io.read_exact(&mut len_buf).await?;
        // let msg_len = u32::from_be_bytes(len_buf) as usize;
        //
        // let mut msg_buf = vec![0u8; msg_len];
        // io.read_exact(&mut msg_buf).await?;
        //
        // let env = Envelope::decode_from_slice(&msg_buf);
        // //.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        // match env {
        //     Ok(env) => {
        //         debug!("read handshake response");
        //         Ok(env) },
        //     Err(e) => {
        //         debug!(?e, "error decoding envelope");
        //         Err(io::Error::new(io::ErrorKind::InvalidData, e))
        //     }
        // }
        debug!("reading handshake response");
        match read_varint_length(io).await {
            Ok(msg_len) => {
                let mut msg_buf = vec![0u8; msg_len];
                io.read_exact(&mut msg_buf).await?;
                let env = Envelope::decode_from_slice(&msg_buf)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                debug!("read handshake response");
                Ok(env)
            }
            Err(error) => {
                debug!(?error, "error reading handshake response");
                Err(io::Error::new(io::ErrorKind::InvalidData, "invalid varint"))
            }
        }
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
        // Write the varint length prefix.
        write_varint_length(io, raw.len()).await?;
        // Write the message bytes.
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

        let len = (raw.len() as u32).to_be_bytes();
        io.write_all(&len).await?;
        io.write_all(&raw).await?;
        let r = io.close().await;
        debug!("wrote handshake response");
        r
    }
}
