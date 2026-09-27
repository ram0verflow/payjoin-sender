//! Regtest receiver for the Java sender: bitcoind, directory, relay, and payjoin-cli.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::sync::mpsc;
use std::time::Duration;

use bitcoin::{Address, Amount, Network};
use payjoin_test_utils::{init_bitcoind_sender_receiver, TestServices};

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("session-oracle: {err}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let cli = std::env::var("PAYJOIN_CLI").map_err(|err| err.to_string())?;
    let services = TestServices::initialize_with_relays(1).await.map_err(|err| err.to_string())?;
    services.wait_for_services_ready().await.map_err(|err| err.to_string())?;
    let (bitcoind, sender, _receiver) =
        init_bitcoind_sender_receiver(None, None).map_err(|err| err.to_string())?;
    let dir = tempfile::tempdir().map_err(|err| err.to_string())?;
    let cert_path = dir.path().join("localhost.der");
    let keys_path = dir.path().join("ohttp_keys");
    let db_path = dir.path().join("receiver_db");
    std::fs::write(&cert_path, services.cert()).map_err(|err| err.to_string())?;
    let keys = services.fetch_ohttp_keys().await.map_err(|err| err.to_string())?;
    std::fs::write(&keys_path, keys.encode().map_err(|err| err.to_string())?).map_err(|err| err.to_string())?;

    let receiver_rpc = format!("http://{}/wallet/receiver", bitcoind.params.rpc_socket);
    let mut child = Command::new(&cli)
        .arg("--root-certificate")
        .arg(&cert_path)
        .arg("--rpchost")
        .arg(&receiver_rpc)
        .arg("--cookie-file")
        .arg(&bitcoind.params.cookie_file)
        .arg("--db-path")
        .arg(&db_path)
        .arg("--ohttp-relays")
        .arg(services.ohttp_relay_url())
        .arg("receive")
        .arg("54321")
        .arg("--pj-directories")
        .arg(services.directory_url())
        .arg("--ohttp-keys")
        .arg(&keys_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|err| err.to_string())?;
    let bip21 = match read_bip21(&mut child) {
        Ok(bip21) => bip21,
        Err(err) => {
            let _ = child.kill();
            return Err(err);
        }
    };
    let address = bip21
        .strip_prefix("bitcoin:")
        .and_then(|rest| rest.split(['?', '#']).next())
        .ok_or("receiver did not print a bitcoin uri")?;
    let address = Address::from_str(address)
        .map_err(|err| err.to_string())?
        .require_network(Network::Regtest)
        .map_err(|err| err.to_string())?;
    let mut outputs = BTreeMap::new();
    outputs.insert(address, Amount::from_sat(54_321));
    let funded = sender.wallet_create_funded_psbt(vec![], vec![outputs]).map_err(|err| err.to_string())?;
    let unsigned = bitcoin::Psbt::from_str(&funded.psbt).map_err(|err| err.to_string())?;
    let signed = sender.wallet_process_psbt(&unsigned).map_err(|err| err.to_string())?;
    if signed.psbt.contains('\n') {
        return Err("psbt contains a newline".to_string());
    }

    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "BIP21={bip21}").map_err(|err| err.to_string())?;
    writeln!(stdout, "RELAY={}", services.ohttp_relay_url()).map_err(|err| err.to_string())?;
    writeln!(stdout, "PSBT={}", signed.psbt).map_err(|err| err.to_string())?;
    writeln!(stdout, "READY").map_err(|err| err.to_string())?;
    stdout.flush().map_err(|err| err.to_string())?;
    drop(stdout);

    let _ = std::io::stdin().read(&mut [0u8; 1]);
    let _ = child.kill();
    Ok(())
}

fn read_bip21(child: &mut Child) -> Result<String, String> {
    let stdout = child.stdout.take().ok_or("receiver has no stdout")?;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            let Ok(line) = line else { break };
            eprintln!("receiver: {line}");
            if line.to_ascii_uppercase().starts_with("BITCOIN:") {
                let _ = tx.send(line);
            }
        }
    });
    rx.recv_timeout(Duration::from_secs(90)).map_err(|err| err.to_string())
}
