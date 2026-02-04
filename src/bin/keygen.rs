//! Key Generation Tool for 2-of-3 Multisig
//!
//! This tool generates 3 extended key pairs following BIP 48 derivation
//! for use in a P2WSH 2-of-3 multisig wallet.
//!
//! EDUCATIONAL NOTES:
//! - Each key represents a different "signer" (e.g., CEO, CFO, Cold Storage)
//! - The xprv (extended private key) stays SECRET on each signer's device
//! - The xpub (extended public key) is shared with the Coordinator
//! - The fingerprint identifies which master key this derivation came from

use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::Network;
use bitcoin::secp256k1::Secp256k1;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::str::FromStr;

/// Represents a key pair with all information needed for PSBT signing
#[derive(Serialize, Deserialize, Debug)]
pub struct KeyData {
    /// Human-readable name (e.g., "key_a", "ceo", "cold_storage")
    pub name: String,
    
    /// Extended Private Key at the derived path (SECRET!)
    /// Format: tprv... (testnet) or xprv... (mainnet)
    pub xprv: String,
    
    /// Extended Public Key at the derived path (share with coordinator)
    /// Format: tpub... (testnet) or xpub... (mainnet)
    pub xpub: String,
    
    /// Master key fingerprint (first 4 bytes of HASH160 of master pubkey)
    /// Used in PSBTs to identify which signer owns this key
    pub fingerprint: String,
    
    /// Full derivation path from master to this key
    /// For BIP 48 P2WSH: m/48'/1'/0'/2' (testnet) or m/48'/0'/0'/2' (mainnet)
    pub derivation_path: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("===========================================");
    println!("   KEY GENERATION FOR 2-of-3 MULTISIG");
    println!("===========================================\n");

    // Create the secp256k1 context for cryptographic operations
    let secp = Secp256k1::new();
    
    // Use Regtest for local development (no real funds at risk)
    let network = Network::Regtest;
    
    // BIP 48 path for P2WSH Multisig
    // m / 48' / coin_type' / account' / script_type'
    // - 48' = BIP 48 purpose (multisig)
    // - 1' = Testnet/Regtest (use 0' for mainnet)
    // - 0' = Account 0
    // - 2' = Script type (P2WSH native SegWit)
    let derivation_path_str = "m/48'/1'/0'/2'";
    let derivation_path = DerivationPath::from_str(derivation_path_str)?;

    println!("Network: {:?}", network);
    println!("Derivation Path: {}", derivation_path_str);
    println!("\n-------------------------------------------\n");

    // Generate 3 key pairs representing our 3 signers
    let signer_names = ["key_a", "key_b", "key_c"];

    for name in signer_names {
        println!("Generating {}...", name);

        // Step 1: Generate random entropy (simulating hardware wallet seed)
        // In production, this comes from BIP 39 mnemonic (12/24 words)
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);

        // Step 2: Create master extended private key from seed
        let master_xprv = Xpriv::new_master(network, &seed)?;
        
        // Step 3: Get the master fingerprint (for PSBT metadata)
        let master_fingerprint = master_xprv.fingerprint(&secp);

        // Step 4: Derive child key at our BIP 48 path
        let derived_xprv = master_xprv.derive_priv(&secp, &derivation_path)?;
        
        // Step 5: Get the public key (this is what we share)
        let derived_xpub = Xpub::from_priv(&secp, &derived_xprv);

        // Create the key data structure
        let key_data = KeyData {
            name: name.to_string(),
            xprv: derived_xprv.to_string(),
            xpub: derived_xpub.to_string(),
            fingerprint: master_fingerprint.to_string(),
            derivation_path: derivation_path_str.to_string(),
        };

        // Save to JSON file
        let filename = format!("{}.json", name);
        let json = serde_json::to_string_pretty(&key_data)?;
        let mut file = File::create(&filename)?;
        file.write_all(json.as_bytes())?;

        println!("  [OK] Fingerprint: {}", master_fingerprint);
        println!("  [OK] Saved to: {}", filename);
        println!();
    }

    println!("-------------------------------------------");
    println!("SUCCESS: Generated 3 key pairs.\n");
    println!("IMPORTANT SECURITY NOTES:");
    println!("  • The 'xprv' fields are SECRETS - never share them!");
    println!("  • In production, xprv stays on the signing device");
    println!("  • Only share 'xpub' and 'fingerprint' with the Coordinator");
    println!("-------------------------------------------");

    Ok(())
}
