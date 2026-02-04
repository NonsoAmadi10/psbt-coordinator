//! PSBT Coordinator - Creates and Manages Unsigned PSBTs
//!
//! The Coordinator's responsibilities:
//! 1. Load all 3 xpubs (never sees private keys)
//! 2. Derive addresses from the multisig descriptor
//! 3. Create unsigned PSBTs with all metadata for signers
//! 4. Combine partial signatures from signers
//! 5. Finalize and broadcast transactions
//!
//! SECURITY MODEL:
//! - Coordinator is "hot" (online, potentially compromised)
//! - It cannot spend funds alone (needs 2 signatures)
//! - It coordinates the signing process
//!
//! EDUCATIONAL: This file demonstrates:
//! - PSBT creation from scratch
//! - Adding witness UTXO and script metadata
//! - BIP 32 derivation info for each signer

use base64::{engine::general_purpose::STANDARD, Engine};
use bitcoin::bip32::DerivationPath;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{
    absolute, transaction, Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid,
};
use psbt_coordinator::{print_wallet_summary, MultisigWallet};
use std::str::FromStr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n");
    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║              PSBT COORDINATOR - TRANSACTION BUILDER            ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");
    println!();

    // Step 1: Load the multisig wallet from key files
    println!("[1/6] Loading multisig wallet configuration...\n");
    
    let key_files = ["key_a.json", "key_b.json", "key_c.json"];
    let network = Network::Regtest;
    let wallet = MultisigWallet::from_key_files(&key_files, network)?;

    print_wallet_summary(&wallet);

    // Step 2: Get the receiving address (index 0)
    println!("\n[2/6] Deriving receiving address at index 0...\n");
    
    let receive_index: u32 = 0;
    let receive_address = wallet.derive_address(receive_index, false)?;
    println!("  Receiving Address: {}", receive_address);
    println!();
    println!("  ┌────────────────────────────────────────────────────────────┐");
    println!("  │  INSTRUCTION: Fund this address using Bitcoin Core regtest │");
    println!("  │                                                            │");
    println!("  │  bitcoin-cli -regtest generatetoaddress 101 <address>      │");
    println!("  │  (generates blocks with coinbase to this address)          │");
    println!("  └────────────────────────────────────────────────────────────┘");
    println!();

    // Step 3: Create a simulated UTXO (in production, query from Bitcoin Core)
    println!("[3/6] Creating PSBT with simulated UTXO...\n");
    println!("  NOTE: In production, you would query UTXOs from Bitcoin Core:");
    println!("  bitcoin-cli -regtest listunspent 1 9999999 '[\"<address>\"]'\n");

    // Simulated UTXO for demonstration
    // In production: query this from your Bitcoin node
    let simulated_utxo = TxOut {
        value: Amount::from_sat(100_000_000), // 1 BTC
        script_pubkey: receive_address.script_pubkey(),
    };
    
    // Simulated outpoint (txid:vout)
    let simulated_outpoint = OutPoint {
        txid: Txid::from_str("0000000000000000000000000000000000000000000000000000000000000001")?,
        vout: 0,
    };

    println!("  Simulated UTXO:");
    println!("    TXID: {}", simulated_outpoint.txid);
    println!("    VOUT: {}", simulated_outpoint.vout);
    println!("    Amount: {} satoshis ({} BTC)", 
             simulated_utxo.value.to_sat(), 
             simulated_utxo.value.to_btc());

    // Step 4: Define the transaction outputs
    println!("\n[4/6] Defining transaction outputs...\n");
    
    // Destination address (where we're sending funds)
    // Using a valid regtest address
    let destination_address = Address::from_str("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080")?
        .require_network(network)?;
    let send_amount = Amount::from_sat(50_000_000); // 0.5 BTC
    
    // Change address (index 1, our own wallet)
    let change_address = wallet.derive_address(1, true)?;
    let fee = Amount::from_sat(1000); // 1000 satoshi fee
    let change_amount = simulated_utxo.value - send_amount - fee;

    println!("  Send:   {} sats to {}", send_amount.to_sat(), destination_address);
    println!("  Change: {} sats to {}", change_amount.to_sat(), change_address);
    println!("  Fee:    {} sats", fee.to_sat());

    // Step 5: Build the unsigned transaction
    println!("\n[5/6] Building unsigned transaction...\n");

    let unsigned_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: simulated_outpoint,
            script_sig: ScriptBuf::new(), // Empty for SegWit
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bitcoin::Witness::new(), // Empty, filled when finalized
        }],
        output: vec![
            TxOut {
                value: send_amount,
                script_pubkey: destination_address.script_pubkey(),
            },
            TxOut {
                value: change_amount,
                script_pubkey: change_address.script_pubkey(),
            },
        ],
    };

    println!("  Transaction built:");
    println!("    Inputs: {}", unsigned_tx.input.len());
    println!("    Outputs: {}", unsigned_tx.output.len());
    println!("    Version: {:?}", unsigned_tx.version);

    // Step 6: Create PSBT with all metadata
    println!("\n[6/6] Creating PSBT with signing metadata...\n");

    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)?;

    // Add witness UTXO (amount + script) - critical for signature verification
    psbt.inputs[0].witness_utxo = Some(simulated_utxo.clone());
    println!("  ✓ Added witness_utxo (amount + script)");

    // Add witness script (the actual 2-of-3 multisig script)
    let witness_script = wallet.witness_script(receive_index)?;
    psbt.inputs[0].witness_script = Some(witness_script.clone());
    println!("  ✓ Added witness_script (OP_2 <keys> OP_3 OP_CHECKMULTISIG)");

    // Add BIP 32 derivation paths for each signer
    // This tells each signer how to derive their signing key
    let secp = Secp256k1::new();
    
    for origin in &wallet.xpub_origins {
        // Derive child pubkey at address index
        let child_path = DerivationPath::from_str(&format!("m/{}", receive_index))?;
        let child_xpub = origin.xpub.derive_pub(&secp, &child_path)?;
        let child_pubkey = child_xpub.public_key;
        
        // Build full derivation path: origin_path / address_index
        // origin.derivation_path is already m/48'/1'/0'/2', we need m/48'/1'/0'/2'/0
        let origin_str = origin.derivation_path.to_string();
        let full_path_str = format!("{}/{}", origin_str, receive_index);
        let full_derivation = DerivationPath::from_str(&full_path_str)?;
        
        // Add to PSBT
        psbt.inputs[0].bip32_derivation.insert(
            child_pubkey,
            (origin.fingerprint, full_derivation),
        );
        
        println!("  ✓ Added derivation for [{}]", origin.fingerprint);
    }

    // Serialize to base64 for transport
    let psbt_base64 = STANDARD.encode(psbt.serialize());

    println!();
    println!("═══════════════════════════════════════════════════════════════");
    println!("                     PSBT CREATED SUCCESSFULLY                  ");
    println!("═══════════════════════════════════════════════════════════════");
    println!();
    println!("PSBT (Base64):");
    println!("{}", psbt_base64);
    println!();
    println!("───────────────────────────────────────────────────────────────");
    println!("NEXT STEPS:");
    println!("  1. Send this PSBT to Signer A for first signature");
    println!("  2. Send the signed PSBT to Signer B for second signature");
    println!("  3. Return to Coordinator to finalize and broadcast");
    println!();
    println!("  Use the signer binary:");
    println!("    cargo run --bin signer -- <key_file.json> <psbt_base64>");
    println!("───────────────────────────────────────────────────────────────");

    // Save PSBT to file for easy testing
    std::fs::write("unsigned.psbt", psbt.serialize())?;
    println!("\n  ✓ Saved binary PSBT to: unsigned.psbt");
    
    std::fs::write("unsigned.psbt.base64", &psbt_base64)?;
    println!("  ✓ Saved base64 PSBT to: unsigned.psbt.base64\n");

    Ok(())
}
