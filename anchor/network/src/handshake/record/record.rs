use std::error::Error;

/// The `Record` trait parallels the idea in Go that each record knows how to:
///   - Provide a domain (for signing separation)
///   - Provide a "codec" (payload type)
///   - Marshal to bytes, unmarshal from bytes
pub trait Record {
    const DOMAIN: &'static str;
    const CODEC: &'static [u8];

    fn marshal_record(&self) -> Result<Vec<u8>, Box<dyn Error>>;
    fn unmarshal_record(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>>;
}
