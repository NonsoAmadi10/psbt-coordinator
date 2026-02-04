//! PSBT Signer - Signs PSBTs with a Single Key
//!
//! The Signer's responsibilities:
//! 1. Load ONE private key (its own, never others)
//! 2. Parse incoming PSBT
//! 3. Find inputs that require THIS key's signature
//! 4. Create partial signatures
//! 5. Output the signed PSBT
//!
//! SECURITY MODEL:
//! - Signer is "cold" (air-gapped, secure)
//! - Has access to ONLY its own private key
//! - Cannot create a complete transaction alone
//! - Should verify transaction details before signing!
//!
//! EDUCATIONAL: This file demonstrates:
//! - Parsing PSBTs
//! - Finding derivation paths by fingerprint
//! - Creating ECDSA signatures
//! - Adding partial_sigs to PSBT

use base64::{engine::general_purpose::STANDARD, Engine};
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::ecdsa::Signature as EcdsaSignature;
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use psbt_coordinator::KeyData;
use std::str::FromStr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n");
    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║                  PSBT SIGNER - PARTIAL SIGNATURE               ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");
    println!();

    // Get command line arguments
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 3 {
        eprintln!("Usage: {} <key_file.json> <psbt_base64_or_file>", args[0]);
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  {} key_a.json unsigned.psbt.base64", args[0]);
        eprintln!("  {} key_b.json cHNidP8BAF4...", args[0]);
        std::process::exit(1);
    }

    let key_file = &args[1];
    let psbt_input = &args[2];

    // Step 1: Load the signer's key
    println!("[1/5] Loading signer key from {}...\n", key_file);
    
    let key_data: KeyData = serde_json::from_str(&std::fs::read_to_string(key_file)?)?;
    let xprv = Xpriv::from_str(&key_data.xprv)?;
    let my_fingerprint = key_data.fingerprint.clone();
    
    println!("  Signer: {}", key_data.name);
    println!("  Fingerprint: {}", my_fingerprint);
    println!("  Base Path: {}", key_data.derivation_path);

    // Step 2: Load the PSBT
    println!("\n[2/5] Loading PSBT...\n");
    
    let psbt_bytes = if psbt_input.ends_with(".base64") || psbt_input.ends_with(".psbt.base64") {
        // Read from file
        let content = std::fs::read_to_string(psbt_input)?;
        STANDARD.decode(content.trim())?
    } else if std::path::Path::new(psbt_input).exists() {
        // Binary file
        std::fs::read(psbt_input)?
    } else {
        // Assume it's base64 string
        STANDARD.decode(psbt_input)?
    };
    
    let mut psbt = Psbt::deserialize(&psbt_bytes)?;
    
    println!("  Inputs: {}", psbt.inputs.len());
    println!("  Outputs: {}", psbt.unsigned_tx.output.len());

    // Step 3: Display transaction details for verification
    println!("\n[3/5] TRANSACTION DETAILS (VERIFY BEFORE SIGNING!)");
    println!("───────────────────────────────────────────────────────────────");
    
    for (i, input) in psbt.inputs.iter().enumerate() {
        if let Some(utxo) = &input.witness_utxo {
            println!("  Input {}:", i);
            println!("    Amount: {} sats ({} BTC)", utxo.value.to_sat(), utxo.value.to_btc());
        }
    }
    
    let mut total_output = 0u64;
    for (i, output) in psbt.unsigned_tx.output.iter().enumerate() {
        println!("  Output {}:", i);
        println!("    Amount: {} sats", output.value.to_sat());
        println!("    Script: {}", output.script_pubkey);
        total_output += output.value.to_sat();
    }
    
    let total_input: u64 = psbt.inputs.iter()
        .filter_map(|i| i.witness_utxo.as_ref())
        .map(|u| u.value.to_sat())
        .sum();
    
    let fee = total_input.saturating_sub(total_output);
    println!();
    println!("  Total In:  {} sats", total_input);
    println!("  Total Out: {} sats", total_output);
    println!("  Fee:       {} sats", fee);
    println!("───────────────────────────────────────────────────────────────");

    // Step 4: Sign inputs that belong to us
    println!("\n[4/5] Signing inputs...\n");

    let secp = Secp256k1::new();
    let mut signed_count = 0;

    // We need to clone the transaction for sighash computation
    let tx = psbt.unsigned_tx.clone();
    
    for input_index in 0..psbt.inputs.len() {
        println!("  Checking input {}...", input_index);
        
        // Check if any derivation in this input matches our fingerprint
        let mut found_key = None;
        
        for (pubkey, (fingerprint, path)) in &psbt.inputs[input_index].bip32_derivation {
            let fp_str = fingerprint.to_string();
            if fp_str == my_fingerprint {
                println!("    ✓ Found our key! Path: {}", path);
                found_key = Some((pubkey.clone(), path.clone()));
                break;
            }
        }

        let Some((target_pubkey, derivation_path)) = found_key else {
            println!("    ✗ No key for our fingerprint, skipping");
            continue;
        };

        // Derive the private key at the required path
        // Our xprv is already at the base path, so we need the child derivation
        // The PSBT path is full (m/48'/1'/0'/2'/0), our xprv is at m/48'/1'/0'/2'
        // So we need just the last component (address index)
        
        // Get the child index from the path (last component)
        let child_index = derivation_path
            .into_iter()
            .last()
            .ok_or("Empty derivation path")?;
        
        let child_path = DerivationPath::from_str(&format!("m/{}", child_index))?;
        let signing_key = xprv.derive_priv(&secp, &child_path)?;
        
        // Verify we derived the right key
        let derived_secp_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &signing_key.private_key);
        let derived_pubkey = bitcoin::PublicKey::new(derived_secp_pubkey);
        
        if derived_secp_pubkey != target_pubkey {
            println!("    ✗ Derived key mismatch! Skipping.");
            continue;
        }
        
        println!("    ✓ Key derived and verified");

        // Get the witness script for sighash computation
        let witness_script = psbt.inputs[input_index]
            .witness_script
            .as_ref()
            .ok_or("Missing witness script")?;
        
        // Get the UTXO value for SegWit sighash
        let utxo_value = psbt.inputs[input_index]
            .witness_utxo
            .as_ref()
            .ok_or("Missing witness UTXO")?
            .value;

        // Compute the sighash (SegWit BIP143 format)
        let mut sighash_cache = SighashCache::new(&tx);
        let sighash = sighash_cache.p2wsh_signature_hash(
            input_index,
            witness_script,
            utxo_value,
            EcdsaSighashType::All,
        )?;

        println!("    ✓ Sighash computed: {}...", &sighash.to_string()[..16]);

        // Create the ECDSA signature
        let message = Message::from_digest(*sighash.as_byte_array());
        let sig = secp.sign_ecdsa(&message, &signing_key.private_key);
        
        // Create Bitcoin signature with sighash type
        let ecdsa_sig = EcdsaSignature::sighash_all(sig);

        // Add partial signature to PSBT
        psbt.inputs[input_index].partial_sigs.insert(
            derived_pubkey,
            ecdsa_sig,
        );
        
        println!("    ✓ Signature added to PSBT");
        signed_count += 1;
    }

    // Step 5: Output the signed PSBT
    println!("\n[5/5] Exporting signed PSBT...\n");

    let signed_psbt_base64 = STANDARD.encode(psbt.serialize());

    println!("═══════════════════════════════════════════════════════════════");
    println!("                     SIGNING COMPLETE                           ");
    println!("═══════════════════════════════════════════════════════════════");
    println!();
    println!("  Inputs signed: {}", signed_count);
    println!();
    println!("Signed PSBT (Base64):");
    println!("{}", signed_psbt_base64);
    println!();
    
    // Count total signatures
    let total_sigs: usize = psbt.inputs.iter()
        .map(|i| i.partial_sigs.len())
        .sum();
    
    if total_sigs >= 2 {
        println!("───────────────────────────────────────────────────────────────");
        println!("  ✓ Threshold reached! ({}/2 signatures)", total_sigs);
        println!("  Ready to finalize with: cargo run --bin finalizer -- <psbt>");
        println!("───────────────────────────────────────────────────────────────");
    } else {
        println!("───────────────────────────────────────────────────────────────");
        println!("  Signatures collected: {}/2 needed", total_sigs);
        println!("  Send to another signer: cargo run --bin signer -- key_X.json <psbt>");
        println!("───────────────────────────────────────────────────────────────");
    }

    // Save signed PSBT
    let output_name = format!("signed_by_{}.psbt.base64", key_data.name);
    std::fs::write(&output_name, &signed_psbt_base64)?;
    println!("\n  ✓ Saved to: {}\n", output_name);

    Ok(())
}
