//! Creates unsigned PSBTs for 3-of-5 multisig transactions.

use base64::{Engine, engine::general_purpose::STANDARD};
use bitcoin::bip32::DerivationPath;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    absolute, transaction,
};
use psbt_coordinator::{MultisigWallet, print_wallet_info};
use std::str::FromStr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_files = [
        "key_a.json",
        "key_b.json",
        "key_c.json",
        "key_d.json",
        "key_e.json",
    ];
    let network = Network::Regtest;
    let wallet = MultisigWallet::from_key_files(&key_files, network)?;

    println!("Loading wallet...\n");
    print_wallet_info(&wallet);

    let addr_index: u32 = 0;
    let receive_addr = wallet.derive_address(addr_index)?;
    println!("\nReceive address: {}", receive_addr);

    // Simulated UTXO - in production, query from Bitcoin Core
    let utxo = TxOut {
        value: Amount::from_sat(100_000_000),
        script_pubkey: receive_addr.script_pubkey(),
    };
    let outpoint = OutPoint {
        txid: Txid::from_str("0000000000000000000000000000000000000000000000000000000000000001")?,
        vout: 0,
    };

    let dest = Address::from_str("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080")?
        .require_network(network)?;
    let send_amt = Amount::from_sat(50_000_000);
    let fee = Amount::from_sat(1000);
    let change_amt = utxo.value - send_amt - fee;
    let change_addr = wallet.derive_address(1)?;

    println!("\nBuilding transaction:");
    println!("  Send: {} sat -> {}", send_amt.to_sat(), dest);
    println!("  Change: {} sat -> {}", change_amt.to_sat(), change_addr);
    println!("  Fee: {} sat", fee.to_sat());

    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![
            TxOut {
                value: send_amt,
                script_pubkey: dest.script_pubkey(),
            },
            TxOut {
                value: change_amt,
                script_pubkey: change_addr.script_pubkey(),
            },
        ],
    };

    let mut psbt = Psbt::from_unsigned_tx(tx)?;
    psbt.inputs[0].witness_utxo = Some(utxo.clone());
    psbt.inputs[0].witness_script = Some(wallet.witness_script(addr_index)?);

    let secp = Secp256k1::new();
    for origin in &wallet.xpub_origins {
        let child_path = DerivationPath::from_str(&format!("m/{}", addr_index))?;
        let child_xpub = origin.xpub.derive_pub(&secp, &child_path)?;
        let full_path =
            DerivationPath::from_str(&format!("{}/{}", origin.derivation_path, addr_index))?;
        psbt.inputs[0]
            .bip32_derivation
            .insert(child_xpub.public_key, (origin.fingerprint, full_path));
    }

    let psbt_b64 = STANDARD.encode(psbt.serialize());
    std::fs::write("unsigned.psbt", psbt.serialize())?;
    std::fs::write("unsigned.psbt.base64", &psbt_b64)?;

    println!("\nPSBT created: unsigned.psbt.base64");
    println!("\nNext: cargo run --bin signer -- key_a.json unsigned.psbt.base64");

    Ok(())
}
