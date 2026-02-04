//! Generates 3 key pairs for 2-of-3 multisig (BIP 48 P2WSH).

use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Network;
use rand::RngCore;
use serde::Serialize;
use std::fs;
use std::str::FromStr;

#[derive(Serialize)]
struct KeyData {
    name: String,
    xprv: String,
    xpub: String,
    fingerprint: String,
    derivation_path: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let network = Network::Regtest;
    let path_str = "m/48'/1'/0'/2'";
    let path = DerivationPath::from_str(path_str)?;

    println!("Generating keys for 2-of-3 multisig");
    println!("Network: {:?}, Path: {}\n", network, path_str);

    for name in ["key_a", "key_b", "key_c"] {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);

        let master = Xpriv::new_master(network, &seed)?;
        let fingerprint = master.fingerprint(&secp);
        let derived = master.derive_priv(&secp, &path)?;
        let xpub = Xpub::from_priv(&secp, &derived);

        let data = KeyData {
            name: name.into(),
            xprv: derived.to_string(),
            xpub: xpub.to_string(),
            fingerprint: fingerprint.to_string(),
            derivation_path: path_str.into(),
        };

        let filename = format!("{}.json", name);
        fs::write(&filename, serde_json::to_string_pretty(&data)?)?;
        println!("{}: {} -> {}", name, fingerprint, filename);
    }

    println!("\nKeys generated. Keep xprv secret, share only xpub with coordinator.");
    Ok(())
}
