//! Test-only oracle. bitcoin-ohttp is the crate rust-payjoin uses.

use bitcoin_ohttp::hpke::{Aead, Kdf, Kem};
use bitcoin_ohttp::{KeyConfig, Server, SymmetricSuite};
use secp256k1::PublicKey;
use std::io::{self, Read, Write};

const ENCAPSULATED: usize = 8192;
const DUMMY32: [u8; 32] = [
    0x5d, 0xf6, 0xe0, 0xe2, 0x76, 0x13, 0x59, 0xd3, 0x0a, 0x82, 0x75, 0x05, 0x8e, 0x29, 0x9f, 0xcc,
    0x03, 0x81, 0x53, 0x45, 0x45, 0xf5, 0x5c, 0xf4, 0x3e, 0x41, 0x98, 0x3f, 0x5d, 0x4c, 0x94, 0x56,
];

fn main() {
    let config = KeyConfig::derive(
        1,
        Kem::K256Sha256,
        vec![SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305)],
        &DUMMY32,
    )
    .expect("key config");
    let encoded = config.encode().expect("encode");
    let public = PublicKey::from_slice(&encoded[3..68]).expect("public key");
    let mut stdout = io::stdout().lock();
    stdout.write_all(&[encoded[0]]).unwrap();
    stdout.write_all(&public.serialize()).unwrap();
    stdout.flush().unwrap();

    let mut request = vec![0u8; ENCAPSULATED];
    io::stdin().lock().read_exact(&mut request).expect("request");
    let server = Server::new(config).expect("server");
    let (plaintext, probe) = server.decapsulate(&request).expect("decapsulate");
    let overhead = probe.encapsulate(&[]).expect("probe").len();
    let (_, response_ctx) = server.decapsulate(&request).expect("decapsulate again");
    let mut message = bhttp::Message::response(bhttp::StatusCode::try_from(200u16).unwrap());
    message.write_content(b"ok");
    let mut padded = vec![0u8; ENCAPSULATED - overhead];
    message
        .write_bhttp(bhttp::Mode::KnownLength, &mut padded.as_mut_slice())
        .unwrap();
    let encapsulated = response_ctx.encapsulate(&padded).expect("response");
    assert_eq!(encapsulated.len(), ENCAPSULATED);
    let mut out = io::stdout().lock();
    out.write_all(&(plaintext.len() as u32).to_be_bytes()).unwrap();
    out.write_all(&plaintext).unwrap();
    out.write_all(&encapsulated).unwrap();
}
