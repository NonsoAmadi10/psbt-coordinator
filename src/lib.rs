//! Shared types for 2-of-3 multisig PSBT coordinator.

use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Network, ScriptBuf};
use miniscript::descriptor::{Descriptor, DescriptorPublicKey};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyData {
    pub name: String,
    pub xprv: String,
    pub xpub: String,
    pub fingerprint: String,
    pub derivation_path: String,
}

#[derive(Debug, Clone)]
pub struct XpubOrigin {
    pub xpub: Xpub,
    pub fingerprint: Fingerprint,
    pub derivation_path: DerivationPath,
}

#[derive(Debug, Clone)]
pub struct MultisigWallet {
    pub descriptor: Descriptor<DescriptorPublicKey>,
    pub network: Network,
    pub threshold: usize,
    pub xpub_origins: Vec<XpubOrigin>,
}

impl MultisigWallet {
    pub fn from_key_files(key_paths: &[&str], network: Network) -> Result<Self, Box<dyn std::error::Error>> {
        if key_paths.len() != 3 {
            return Err("expected 3 key files".into());
        }

        let mut xpub_origins = Vec::new();
        let mut descriptor_parts = Vec::new();

        for path in key_paths {
            let data: KeyData = serde_json::from_str(&std::fs::read_to_string(path)?)?;
            let xpub = Xpub::from_str(&data.xpub)?;
            let fingerprint = Fingerprint::from_str(&data.fingerprint)?;
            let derivation_path = DerivationPath::from_str(&data.derivation_path)?;

            xpub_origins.push(XpubOrigin { xpub, fingerprint, derivation_path });

            let path_suffix = data.derivation_path.strip_prefix("m/").unwrap_or(&data.derivation_path);
            descriptor_parts.push(format!("[{}/{}]{}/*", data.fingerprint, path_suffix, data.xpub));
        }

        let descriptor_str = format!(
            "wsh(sortedmulti(2,{},{},{}))",
            descriptor_parts[0], descriptor_parts[1], descriptor_parts[2]
        );
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&descriptor_str)?;

        Ok(Self { descriptor, network, threshold: 2, xpub_origins })
    }

    pub fn derive_address(&self, index: u32) -> Result<Address, Box<dyn std::error::Error>> {
        let derived = self.descriptor.at_derivation_index(index)?;
        let script_pubkey = derived.script_pubkey();
        Ok(Address::from_script(&script_pubkey, self.network)?)
    }

    pub fn witness_script(&self, index: u32) -> Result<ScriptBuf, Box<dyn std::error::Error>> {
        let derived = self.descriptor.at_derivation_index(index)?;
        if let Descriptor::Wsh(wsh) = derived {
            Ok(wsh.inner_script())
        } else {
            Err("expected WSH descriptor".into())
        }
    }

    pub fn derive_child_pubkey(&self, origin: &XpubOrigin, index: u32) -> Result<bitcoin::secp256k1::PublicKey, Box<dyn std::error::Error>> {
        let secp = Secp256k1::new();
        let child_path = DerivationPath::from_str(&format!("m/{}", index))?;
        let child_xpub = origin.xpub.derive_pub(&secp, &child_path)?;
        Ok(child_xpub.public_key)
    }
}

pub fn print_wallet_info(wallet: &MultisigWallet) {
    println!("Network: {:?}", wallet.network);
    println!("Threshold: {}-of-{}", wallet.threshold, wallet.xpub_origins.len());
    println!();
    for (i, origin) in wallet.xpub_origins.iter().enumerate() {
        println!("Signer {}: [{}] {}", i + 1, origin.fingerprint, &origin.xpub.to_string()[..24]);
    }
    println!();
    println!("Descriptor: {}", wallet.descriptor);
    println!();
    for i in 0..3 {
        if let Ok(addr) = wallet.derive_address(i) {
            println!("Address {}: {}", i, addr);
        }
    }
}
