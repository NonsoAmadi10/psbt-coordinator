//! Signs PSBTs using a single key from the multisig set.

use base64::{Engine, engine::general_purpose::STANDARD};
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::ecdsa::Signature as EcdsaSignature;
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use psbt_coordinator::KeyData;
use std::str::FromStr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <key.json> <psbt>", args[0]);
        std::process::exit(1);
    }

    let key_data: KeyData = serde_json::from_str(&std::fs::read_to_string(&args[1])?)?;
    let xprv = Xpriv::from_str(&key_data.xprv)?;
    let my_fp = &key_data.fingerprint;

    println!("Signer: {} [{}]", key_data.name, my_fp);

    let psbt_bytes = load_psbt(&args[2])?;
    let mut psbt = Psbt::deserialize(&psbt_bytes)?;

    print_tx_summary(&psbt);

    let secp = Secp256k1::new();
    let tx = psbt.unsigned_tx.clone();
    let mut signed = 0;

    for idx in 0..psbt.inputs.len() {
        let Some((pubkey, path)) = find_our_key(&psbt.inputs[idx], my_fp) else {
            continue;
        };

        let child_idx = path.into_iter().last().ok_or("empty path")?;
        let child_path = DerivationPath::from_str(&format!("m/{}", child_idx))?;
        let privkey = xprv.derive_priv(&secp, &child_path)?;

        let derived_pub =
            bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &privkey.private_key);
        if derived_pub != pubkey {
            eprintln!("  Input {}: key mismatch, skipping", idx);
            continue;
        }

        let script = psbt.inputs[idx]
            .witness_script
            .as_ref()
            .ok_or("no witness script")?;
        let value = psbt.inputs[idx]
            .witness_utxo
            .as_ref()
            .ok_or("no witness utxo")?
            .value;

        let mut cache = SighashCache::new(&tx);
        let sighash = cache.p2wsh_signature_hash(idx, script, value, EcdsaSighashType::All)?;

        let msg = Message::from_digest(*sighash.as_byte_array());
        let sig = secp.sign_ecdsa(&msg, &privkey.private_key);

        psbt.inputs[idx].partial_sigs.insert(
            bitcoin::PublicKey::new(derived_pub),
            EcdsaSignature::sighash_all(sig),
        );
        signed += 1;
        println!("  Input {}: signed", idx);
    }

    let total_sigs: usize = psbt.inputs.iter().map(|i| i.partial_sigs.len()).sum();
    let out_file = format!("signed_by_{}.psbt.base64", key_data.name);
    std::fs::write(&out_file, STANDARD.encode(psbt.serialize()))?;

    println!(
        "\nSigned {} input(s), total signatures: {}/3",
        signed, total_sigs
    );
    println!("Output: {}", out_file);

    if total_sigs >= 3 {
        println!(
            "\nThreshold met. Run: cargo run --bin finalizer -- {}",
            out_file
        );
    }

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

fn find_our_key(
    input: &bitcoin::psbt::Input,
    fp: &str,
) -> Option<(bitcoin::secp256k1::PublicKey, DerivationPath)> {
    for (pk, (fingerprint, path)) in &input.bip32_derivation {
        if fingerprint.to_string() == fp {
            return Some((*pk, path.clone()));
        }
    }
    None
}

fn print_tx_summary(psbt: &Psbt) {
    let total_in: u64 = psbt
        .inputs
        .iter()
        .filter_map(|i| i.witness_utxo.as_ref())
        .map(|u| u.value.to_sat())
        .sum();
    let total_out: u64 = psbt
        .unsigned_tx
        .output
        .iter()
        .map(|o| o.value.to_sat())
        .sum();

    println!(
        "\nTransaction: {} input(s), {} output(s)",
        psbt.inputs.len(),
        psbt.unsigned_tx.output.len()
    );
    println!("  Total in:  {} sat", total_in);
    println!("  Total out: {} sat", total_out);
    println!("  Fee:       {} sat\n", total_in.saturating_sub(total_out));
}
