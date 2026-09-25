//! Test-only oracle. bitcoin-hpke is not a library dependency.

use bitcoin_hpke::aead::ChaCha20Poly1305;
use bitcoin_hpke::kdf::HkdfSha256;
use bitcoin_hpke::kem::{Kem, SecpK256HkdfSha256};
use bitcoin_hpke::{
    setup_receiver, setup_sender, Deserializable, OpModeR, OpModeS, Serializable,
};
use rand_core::{CryptoRng, RngCore};
use std::io::{self, Read, Write};

type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;
type Suite = SecpK256HkdfSha256;

struct FixedIkm([u8; 32]);

impl RngCore for FixedIkm {
    fn next_u32(&mut self) -> u32 {
        0
    }
    fn next_u64(&mut self) -> u64 {
        0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        assert_eq!(dest.len(), 32, "ephemeral ikm must be 32 bytes");
        dest.copy_from_slice(&self.0);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for FixedIkm {}

fn main() {
    let mut stdin = io::stdin().lock();
    let command = std::env::args().nth(1).expect("command");
    let result = match command.as_str() {
        "open-base" => open_base(&mut stdin),
        "seal-auth" => seal_auth(&mut stdin),
        other => panic!("unknown command {other}"),
    };
    if let Err(error) = result {
        eprintln!("hpke-oracle: {error}");
        std::process::exit(1);
    }
}

fn open_base(input: &mut impl Read) -> io::Result<()> {
    let sk_bytes = read_exact(input, 32)?;
    let enc_bytes = read_exact(input, 65)?;
    let info = read_vec(input)?;
    let ciphertext = read_vec(input)?;
    let sk = <Suite as Kem>::PrivateKey::from_bytes(&sk_bytes).expect("receiver secret");
    let enc = <Suite as Kem>::EncappedKey::from_bytes(&enc_bytes).expect("encapsulated key");
    let opened = setup_receiver::<Aead, Kdf, Suite>(&OpModeR::Base, &sk, &enc, &info)
        .and_then(|mut ctx| ctx.open(&ciphertext, &[]));
    let mut stdout = io::stdout().lock();
    match opened {
        Ok(plaintext) => {
            stdout.write_all(&[0])?;
            write_vec(&mut stdout, &plaintext)?;
        }
        Err(_) => stdout.write_all(&[1])?,
    }
    Ok(())
}

fn seal_auth(input: &mut impl Read) -> io::Result<()> {
    let ikm_e = read_exact(input, 32)?;
    let sk_s_bytes = read_exact(input, 32)?;
    let pk_r_bytes = read_exact(input, 65)?;
    let info = read_vec(input)?;
    let plaintext = read_vec(input)?;
    let sk_s = <Suite as Kem>::PrivateKey::from_bytes(&sk_s_bytes).expect("sender secret");
    let pk_s = Suite::sk_to_pk(&sk_s);
    let pk_r = <Suite as Kem>::PublicKey::from_bytes(&pk_r_bytes).expect("recipient public key");
    let mut ikm = [0u8; 32];
    ikm.copy_from_slice(&ikm_e);
    let (enc, mut ctx) = setup_sender::<Aead, Kdf, Suite, _>(
        &OpModeS::Auth((sk_s, pk_s)),
        &pk_r,
        &info,
        &mut FixedIkm(ikm),
    )
    .expect("auth seal setup");
    let ciphertext = ctx.seal(&plaintext, &[]).expect("auth seal");
    let mut stdout = io::stdout().lock();
    stdout.write_all(&enc.to_bytes())?;
    write_vec(&mut stdout, &ciphertext)?;
    Ok(())
}

fn read_exact(input: &mut impl Read, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    input.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_vec(input: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    input.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    read_exact(input, len)
}

fn write_vec(output: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    output.write_all(&(bytes.len() as u32).to_be_bytes())?;
    output.write_all(bytes)
}
