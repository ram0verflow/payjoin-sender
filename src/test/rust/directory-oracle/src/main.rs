//! Starts the local OHTTP relay and payjoin directory used by the v2 regtest tests.

use std::io::Read;

#[tokio::main]
async fn main() {
    let services = payjoin_test_utils::TestServices::initialize_with_relays(1)
        .await
        .expect("services");
    services.wait_for_services_ready().await.expect("ready");
    let keys = services.fetch_ohttp_keys().await.expect("ohttp keys");
    let encoded = keys.to_bytes().expect("34-byte key");
    println!("RELAY={}", services.ohttp_relay_url());
    println!("DIRECTORY={}", services.directory_url());
    println!("KEYS={}", hex::encode(encoded));
    println!("READY");
    let _ = std::io::stdin().read(&mut [0u8; 1]);
}
