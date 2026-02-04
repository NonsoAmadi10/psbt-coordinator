//! PSBT Finalizer - Combines Signatures and Produces Final Transaction
//!
//! The Finalizer's responsibilities:
//! 1. Import PSBT with sufficient signatures (M of N)
//! 2. Verify signature validity
//! 3. Construct the final witness stack
//! 4. Extract the signed transaction
//! 5. Output transaction for broadcast
//!
//! EDUCATIONAL: This file demonstrates:
//! - PSBT finalization
//! - Witness stack construction for P2WSH multisig
//! - Transaction serialization

use base64::{engine::general_purpose::STANDARD, Engine};
use bitcoin::psbt::Psbt;
use bitcoin::consensus::encode;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n");
    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║                PSBT FINALIZER - TRANSACTION BUILDER            ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");
    println!();

    // Get command line arguments
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Usage: {} <psbt_base64_or_file>", args[0]);
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  {} signed_by_key_b.psbt.base64", args[0]);
        eprintln!("  {} cHNidP8BAF4...", args[0]);
        std::process::exit(1);
    }

    let psbt_input = &args[1];

    // Step 1: Load the PSBT
    println!("[1/4] Loading PSBT...\n");
    
    let psbt_bytes = if psbt_input.ends_with(".base64") || psbt_input.ends_with(".psbt.base64") {
        let content = std::fs::read_to_string(psbt_input)?;
        STANDARD.decode(content.trim())?
    } else if std::path::Path::new(psbt_input).exists() {
        std::fs::read(psbt_input)?
    } else {
        STANDARD.decode(psbt_input)?
    };
    
    let mut psbt = Psbt::deserialize(&psbt_bytes)?;
    
    println!("  Inputs: {}", psbt.inputs.len());
    println!("  Outputs: {}", psbt.unsigned_tx.output.len());

    // Step 2: Check signature count
    println!("\n[2/4] Checking signatures...\n");
    
    for (i, input) in psbt.inputs.iter().enumerate() {
        let sig_count = input.partial_sigs.len();
        println!("  Input {}: {} signatures", i, sig_count);
        
        for (pubkey, sig) in &input.partial_sigs {
            let pk_hex = pubkey.to_string();
            println!("    - {}...{}", &pk_hex[..8], &pk_hex[pk_hex.len()-8..]);
        }
        
        if sig_count < 2 {
            eprintln!("\n  [X] ERROR: Input {} has insufficient signatures ({}/2)", i, sig_count);
            eprintln!("    Need at least 2 signatures for 2-of-3 multisig.");
            std::process::exit(1);
        }
    }
    
    println!("\n  [OK] All inputs have sufficient signatures");

    // Step 3: Finalize the PSBT
    println!("\n[3/4] Finalizing PSBT...\n");
    
    // Use miniscript to finalize (handles witness construction automatically)
    let finalized_psbt = finalize_psbt(psbt)?;
    
    println!("  [OK] PSBT finalized");

    // Step 4: Extract the final transaction
    println!("\n[4/4] Extracting signed transaction...\n");
    
    let final_tx = finalized_psbt.extract_tx()?;
    
    // Serialize for broadcast
    let tx_hex = encode::serialize_hex(&final_tx);
    
    println!("═══════════════════════════════════════════════════════════════");
    println!("                   TRANSACTION READY FOR BROADCAST              ");
    println!("═══════════════════════════════════════════════════════════════");
    println!();
    println!("  TXID: {}", final_tx.compute_txid());
    println!("  Size: {} vbytes", final_tx.vsize());
    println!("  Weight: {} WU", final_tx.weight());
    println!();
    println!("Signed Transaction (Hex):");
    println!("{}", tx_hex);
    println!();
    println!("───────────────────────────────────────────────────────────────");
    println!("BROADCAST COMMANDS:");
    println!();
    println!("  Using Bitcoin Core:");
    println!("    bitcoin-cli -regtest sendrawtransaction {}", &tx_hex[..40]);
    println!();
    println!("  Using electrs/blockstream API:");
    println!("    curl -X POST -d '{}' https://...", &tx_hex[..20]);
    println!("───────────────────────────────────────────────────────────────");

    // Save transaction
    std::fs::write("final_tx.hex", &tx_hex)?;
    println!("\n  [OK] Saved to: final_tx.hex\n");

    Ok(())
}

/// Finalize a PSBT by constructing the witness for each input
fn finalize_psbt(mut psbt: Psbt) -> Result<Psbt, Box<dyn std::error::Error>> {
    use bitcoin::Witness;
    
    for input_index in 0..psbt.inputs.len() {
        let input = &psbt.inputs[input_index];
        
        // Get the witness script
        let witness_script = input.witness_script
            .as_ref()
            .ok_or("Missing witness script")?
            .clone();
        
        // Sort signatures by public key (to match sortedmulti order)
        let mut sigs: Vec<_> = input.partial_sigs.iter().collect();
        sigs.sort_by(|a, b| a.0.inner.serialize().cmp(&b.0.inner.serialize()));
        
        // Take only the first 2 signatures (for 2-of-3)
        let selected_sigs: Vec<_> = sigs.into_iter().take(2).collect();
        
        // Build witness stack for P2WSH multisig:
        // <empty> <sig1> <sig2> <witness_script>
        let mut witness = Witness::new();
        
        // Push empty element (CHECKMULTISIG bug workaround)
        witness.push([]);
        
        // Push signatures (in pubkey order)
        for (_, sig) in &selected_sigs {
            witness.push(sig.serialize());
        }
        
        // Push witness script
        witness.push(witness_script.as_bytes());
        
        // Set the final witness
        psbt.inputs[input_index].final_script_witness = Some(witness);
        
        // Clear out the fields that are no longer needed (but keep witness_utxo for vsize calc)
        psbt.inputs[input_index].partial_sigs.clear();
        psbt.inputs[input_index].bip32_derivation.clear();
        psbt.inputs[input_index].witness_script = None;
        // Note: We keep witness_utxo for extract_tx to work correctly
    }
    
    Ok(psbt)
}
