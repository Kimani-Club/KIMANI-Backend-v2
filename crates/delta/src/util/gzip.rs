//! Gzip response compression.
//!
//! Rocket 0.5 has no built-in compression (it lived in `rocket_contrib` in 0.4
//! and was dropped), and delta was shipping every JSON body — message pages,
//! server objects, the unbounded member+user list — uncompressed. On a 3G link
//! that transfer time dominates. This fairing gzips response bodies for clients
//! that accept it. JSON of this shape compresses ~5-10x.
//!
//! `on_response` reads the (streaming) body to bytes, which *consumes* it, so
//! every path must set a body back — the compressed one, or the original bytes
//! unchanged when we decline.

use std::io::{Cursor, Write};

use flate2::write::GzEncoder;
use flate2::Compression;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Header;
use rocket::tokio::io::AsyncReadExt;
use rocket::{Request, Response};

/// Below this the gzip header + trailer costs more than it saves.
const MIN_GZIP_BYTES: usize = 1024;

pub struct GzipFairing;

#[rocket::async_trait]
impl Fairing for GzipFairing {
    fn info(&self) -> Info {
        Info {
            name: "Gzip Compression",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        // Only for clients that asked for it.
        let accepts_gzip = request
            .headers()
            .get("Accept-Encoding")
            .any(|value| value.to_ascii_lowercase().contains("gzip"));
        if !accepts_gzip {
            return;
        }

        // Never double-encode (e.g. an already-gzipped asset).
        if response.headers().contains("Content-Encoding") {
            return;
        }

        // Reading drains the body; from here we MUST set one back on every path.
        let mut body = Vec::new();
        if response.body_mut().read_to_end(&mut body).await.is_err() {
            return; // body already gone; nothing we can safely do
        }

        if body.len() < MIN_GZIP_BYTES {
            response.set_sized_body(body.len(), Cursor::new(body));
            return;
        }

        let mut encoder = GzEncoder::new(Vec::with_capacity(body.len() / 2), Compression::default());
        let compressed = match encoder.write_all(&body).and_then(|_| encoder.finish()) {
            Ok(compressed) => compressed,
            Err(_) => {
                // Compression failed — put the original body back untouched.
                response.set_sized_body(body.len(), Cursor::new(body));
                return;
            }
        };

        response.set_header(Header::new("Content-Encoding", "gzip"));
        // Caches must not hand a gzipped body to a client that can't decode it.
        response.set_header(Header::new("Vary", "Accept-Encoding"));
        response.set_sized_body(compressed.len(), Cursor::new(compressed));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The one piece of real logic worth pinning: a body over the threshold
    // round-trips through gzip smaller and decodes back to the original.
    #[test]
    fn gzips_and_round_trips() {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let original = "{\"members\":[\"".to_string() + &"a".repeat(5000) + "\"]}";
        let input = original.as_bytes();
        assert!(input.len() >= MIN_GZIP_BYTES);

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(input).unwrap();
        let compressed = encoder.finish().unwrap();
        assert!(compressed.len() < input.len(), "gzip should shrink a repetitive JSON body");

        let mut decoder = GzDecoder::new(Cursor::new(compressed));
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, input, "gzip must be lossless");
    }
}
