//! Finalizes PSBTs and extracts broadcast-ready transactions.

use base64::{Engine, engine::general_purpose::STANDARD};
use bitcoin::Witness;
use bitcoin::consensus::encode;
use bitcoin::psbt::Psbt;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <psbt>", args[0]);
        std::process::exit(1);
    }

    let psbt_bytes = load_psbt(&args[1])?;
    let mut psbt = Psbt::deserialize(&psbt_bytes)?;

    // Verify sufficient signatures
    for (i, input) in psbt.inputs.iter().enumerate() {
        let sigs = input.partial_sigs.len();
        if sigs < 3 {
            eprintln!("Input {}: only {}/3 signatures", i, sigs);
            std::process::exit(1);
        }
        println!("Input {}: {} signatures", i, sigs);
    }

    // Finalize each input
    for idx in 0..psbt.inputs.len() {
        let input = &psbt.inputs[idx];
        let script = input
            .witness_script
            .as_ref()
            .ok_or("missing witness script")?
            .clone();

        // Sort sigs by pubkey for sortedmulti
        let mut sigs: Vec<_> = input.partial_sigs.iter().collect();
        sigs.sort_by(|a, b| a.0.inner.serialize().cmp(&b.0.inner.serialize()));

        // Build witness: <empty> <sig1> <sig2> <sig3> <script>
        let mut witness = Witness::new();
        witness.push([]);
        for (_, sig) in sigs.iter().take(3) {
            witness.push(sig.serialize());
        }
        witness.push(script.as_bytes());

        psbt.inputs[idx].final_script_witness = Some(witness);
        psbt.inputs[idx].partial_sigs.clear();
        psbt.inputs[idx].bip32_derivation.clear();
        psbt.inputs[idx].witness_script = None;
    }

    let tx = psbt.extract_tx()?;
    let tx_hex = encode::serialize_hex(&tx);

    std::fs::write("final_tx.hex", &tx_hex)?;

    println!("\nTransaction finalized");
    println!("  TXID: {}", tx.compute_txid());
    println!("  Size: {} vbytes", tx.vsize());
    println!("  Output: final_tx.hex");
    println!("\nBroadcast: bitcoin-cli -regtest sendrawtransaction $(cat final_tx.hex)");

    Ok(())
}

fn load_psbt(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if input.ends_with(".base64") {
        Ok(STANDARD.decode(std::fs::read_to_string(input)?.trim())?)
    } else if std::path::Path::new(input).exists() {
        Ok(std::fs::read(input)?)
    } else {
        Ok(STANDARD.decode(input)?)
    }
}
