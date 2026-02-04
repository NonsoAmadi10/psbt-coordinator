# PSBT Coordinator

A Rust implementation of 2-of-3 multisig Bitcoin custody infrastructure using PSBTs (Partially Signed Bitcoin Transactions).

## Overview

This project demonstrates production-grade patterns for Bitcoin custody:

- 2-of-3 multisig using P2WSH (Pay-to-Witness-Script-Hash)
- BIP 32/48 hierarchical deterministic key derivation
- BIP 174 PSBT workflow for air-gapped signing
- Role separation between Coordinator and Signers

## Prerequisites

- Rust 1.70 or later
- Cargo package manager

Optional (for real transaction testing):
- Bitcoin Core with regtest mode

## Installation

```bash
git clone <repository-url>
cd psbt-coordinator
cargo build --release
```

## Project Structure

```
psbt-coordinator/
├── src/
│   ├── lib.rs              # Shared types (MultisigWallet, KeyData)
│   ├── main.rs             # Entry point
│   └── bin/
│       ├── keygen.rs       # Generate 3 key pairs for multisig
│       ├── coordinator.rs  # Create unsigned PSBTs
│       ├── signer.rs       # Sign PSBTs with individual keys
│       └── finalizer.rs    # Finalize and extract transactions
├── docs/                   # Educational blog series
│   ├── 01_foundations.md
│   ├── 02_keys_and_descriptors.md
│   ├── 03_psbt_construction.md
│   ├── 04_role_separation.md
│   └── 05_psbt_combining.md
└── key_*.json              # Generated key files (not committed)
```

## Usage

### Step 1: Generate Keys

Generate 3 key pairs for the 2-of-3 multisig wallet:

```bash
cargo run --bin keygen
```

This creates `key_a.json`, `key_b.json`, and `key_c.json` containing:
- Extended private key (xprv) - SECRET, stays on signing device
- Extended public key (xpub) - shared with coordinator
- Master fingerprint - identifies the key in PSBTs
- Derivation path (m/48'/1'/0'/2' for testnet P2WSH)

### Step 2: Create Unsigned PSBT

The coordinator creates a PSBT with all metadata needed for signing:

```bash
cargo run --bin coordinator
```

This outputs:
- `unsigned.psbt` - binary PSBT
- `unsigned.psbt.base64` - base64-encoded PSBT for transport

### Step 3: Sign with First Key

Send the PSBT to the first signer:

```bash
cargo run --bin signer -- key_a.json unsigned.psbt.base64
```

The signer will:
1. Display transaction details for verification
2. Find inputs requiring this key's signature
3. Create and add partial signature
4. Output `signed_by_key_a.psbt.base64`

### Step 4: Sign with Second Key

Send the partially-signed PSBT to the second signer:

```bash
cargo run --bin signer -- key_b.json signed_by_key_a.psbt.base64
```

This adds the second signature, reaching the 2-of-3 threshold.

### Step 5: Finalize Transaction

The coordinator finalizes the PSBT and extracts the transaction:

```bash
cargo run --bin finalizer -- signed_by_key_b.psbt.base64
```

This outputs:
- `final_tx.hex` - the signed transaction ready for broadcast

### Step 6: Broadcast (requires Bitcoin Core)

```bash
bitcoin-cli -regtest sendrawtransaction $(cat final_tx.hex)
```

## Security Model

```
COORDINATOR (Hot/Online)
- Knows: All 3 xpubs
- Creates: Unsigned PSBTs
- Combines: Partial signatures
- CANNOT: Create valid signatures

SIGNER A/B/C (Cold/Air-gapped)
- Knows: Only its own xprv
- Signs: With its own key
- Verifies: Transaction details
- CANNOT: See other keys or sign alone
```

No single component can spend funds unilaterally. The coordinator never sees private keys, and each signer knows only its own key.

## Testing with Bitcoin Core Regtest

1. Start Bitcoin Core in regtest mode:
```bash
bitcoind -regtest -daemon
```

2. Generate blocks to the multisig address:
```bash
# Get the address from coordinator output
cargo run --bin coordinator 2>&1 | grep "Receiving Address"

# Fund it
bitcoin-cli -regtest generatetoaddress 101 <address>
```

3. Update coordinator.rs with real UTXO data from:
```bash
bitcoin-cli -regtest listunspent 1 9999999 '["<address>"]'
```

4. Run the full workflow and broadcast.

## Documentation

The `docs/` directory contains an educational blog series covering:

1. **Foundations** - Elliptic curve cryptography, multisig theory, Bitcoin Script
2. **HD Keys and Descriptors** - BIP 32/39/48, fingerprints, output descriptors
3. **PSBT Construction** - BIP 174, PSBT structure and lifecycle
4. **Role Separation** - Coordinator vs Signer architecture
5. **PSBT Combining** - Merging signatures and finalization

## Dependencies

- `bitcoin` - Bitcoin primitives and serialization
- `miniscript` - Output descriptor parsing
- `secp256k1` - Elliptic curve operations
- `base64` - PSBT encoding
- `serde` / `serde_json` - Key file serialization
- `rand` - Cryptographic randomness

## License

MIT