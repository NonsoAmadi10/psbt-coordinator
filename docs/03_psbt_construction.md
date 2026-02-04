# Building Bitcoin Custody Infrastructure: Part 3 - PSBT Construction

## What You Will Learn
- What PSBTs are and why they exist
- PSBT structure and fields
- Creating a PSBT for 2-of-3 multisig
- How PSBTs enable air-gapped signing

---

## Chapter 1: The Problem PSBTs Solve

### Before PSBTs: A Security Nightmare

Imagine you're signing a Bitcoin transaction on a hardware wallet:

```
OLD WAY:
                                                          
  ┌────────────┐     Raw Transaction      ┌────────────┐
  │   Online   │  ──────────────────────► │  Hardware  │
  │  Computer  │                          │   Wallet   │
  └────────────┘                          └────────────┘
         ▲                                       │
         │         Signed Transaction            │
         └───────────────────────────────────────┘
```

**Problems:**
1. Hardware wallet sees only raw bytes - can't verify amounts
2. Each wallet software had its own format
3. No metadata about UTXOs, derivation paths, or scripts
4. Multisig coordination was a nightmare

### PSBTs: A Universal Standard

**BIP 174** (Partially Signed Bitcoin Transaction) defines a standard container that carries:
- The unsigned transaction
- All metadata needed to sign
- Partial signatures as they're collected

```
PSBT WAY:
                                                          
  ┌────────────┐         PSBT               ┌────────────┐
  │ Coordinator│  ──────────────────────►  │  Signer A  │
  │            │  (unsigned + metadata)    │ (adds sig) │
  └────────────┘                           └──────┬─────┘
         ▲                                        │
         │                                        ▼
         │                                 ┌────────────┐
         │              PSBT               │  Signer B  │
         │◄────────────────────────────────│ (adds sig) │
         │         (with 2 signatures)     └────────────┘
         │
         ▼
  ┌────────────┐
  │  Finalize  │
  │ & Broadcast│
  └────────────┘
```

---

## Chapter 2: PSBT Structure

### The Container Model

A PSBT is NOT a transaction. It's a **container** that holds:

```
┌─────────────────────────────────────────────────────────────────┐
│                            PSBT                                  │
├─────────────────────────────────────────────────────────────────┤
│  GLOBAL MAP                                                      │
│  ├── Unsigned Transaction                                        │
│  ├── Extended Public Keys (xpubs)                               │
│  └── Version                                                     │
├─────────────────────────────────────────────────────────────────┤
│  INPUT MAPS (one per input)                                      │
│  ├── Input 0:                                                    │
│  │   ├── Witness UTXO (amount + scriptPubKey)                   │
│  │   ├── Witness Script (the 2-of-3 multisig script)           │
│  │   ├── BIP 32 Derivation (fingerprint → path → pubkey)       │
│  │   └── Partial Signatures (added by signers)                  │
│  ├── Input 1: ...                                                │
│  └── Input N: ...                                                │
├─────────────────────────────────────────────────────────────────┤
│  OUTPUT MAPS (one per output)                                    │
│  ├── Output 0:                                                   │
│  │   └── BIP 32 Derivation (if change output to our wallet)    │
│  ├── Output 1: ...                                               │
│  └── Output N: ...                                               │
└─────────────────────────────────────────────────────────────────┘
```

### Key Fields Explained

**Global: Unsigned Transaction**
- The raw transaction with empty scriptSigs/witnesses
- Defines: inputs (UTXOs to spend), outputs (destinations)

**Input: Witness UTXO**
- The UTXO being spent (amount + locking script)
- Hardware wallets use this to display "Sending X BTC"
- Critical for fee calculation

**Input: Witness Script**
- For P2WSH, this is the actual script (OP_2 <keys> OP_3 OP_CHECKMULTISIG)
- Needed to create the signature

**Input: BIP 32 Derivation**
- Maps: `public_key → (fingerprint, derivation_path)`
- Each signer scans for their fingerprint
- When found, they derive the private key and sign

**Input: Partial Signature**
- Maps: `public_key → signature`
- Added by each signer
- Once we have M signatures, we can finalize

---

## Chapter 3: PSBT Lifecycle

### Phase 1: Creation (Coordinator)

```
Coordinator:
  1. Select UTXOs to spend
  2. Create unsigned transaction (inputs → outputs)
  3. Add UTXO metadata to each input
  4. Add witness script to each input
  5. Add BIP 32 derivation paths for ALL signers
  6. Export PSBT (base64 or binary)
```

### Phase 2: Signing (Each Signer)

```
Signer A:
  1. Import PSBT
  2. For each input:
     a. Find derivations with MY fingerprint
     b. Derive private key at that path
     c. Create ECDSA signature for that input
     d. Add partial_sig[my_pubkey] = signature
  3. Export updated PSBT

Signer B:
  (Same process, different fingerprint)
```

### Phase 3: Combining (Coordinator)

```
Coordinator:
  1. Import all signed PSBTs
  2. Merge partial signatures into one PSBT
  3. For each input, verify we have M signatures
```

### Phase 4: Finalizing (Coordinator)

```
Coordinator:
  1. For each input:
     a. Build the final witness stack:
        - <empty> (CHECKMULTISIG bug)
        - <sig_1>
        - <sig_2>
        - <witness_script>
     b. Clear all PSBT metadata (no longer needed)
  2. Extract final signed transaction
  3. Broadcast to network
```

---

## Chapter 4: The Signature Sighash

### What Gets Signed?

When signing a Bitcoin transaction, you don't sign the raw transaction. You sign a **commitment hash** (sighash).

For SegWit (BIP 143), the sighash commits to:
```
1. nVersion          (transaction version)
2. hashPrevouts      (hash of all input outpoints)
3. hashSequence      (hash of all input sequences)
4. outpoint          (this input's TXID + vout)
5. scriptCode        (the witness script)
6. amount            (value of this UTXO - NEW in SegWit!)
7. nSequence         (this input's sequence)
8. hashOutputs       (hash of all outputs)
9. nLockTime         (transaction locktime)
10. sighash_type     (usually SIGHASH_ALL = 0x01)
```

**Critical: Amount Commitment**
In legacy Bitcoin, the amount was NOT committed. Attackers could lie about the amount and trick you into paying huge fees. SegWit fixes this.

### Sighash Types

- **SIGHASH_ALL (0x01)**: Sign all inputs and outputs (default, most secure)
- **SIGHASH_NONE (0x02)**: Sign inputs only (anyone can change outputs!)
- **SIGHASH_SINGLE (0x03)**: Sign one specific output
- **SIGHASH_ANYONECANPAY (0x80)**: Can be combined, only sign this input

For custody: **Always use SIGHASH_ALL**. It ensures no one can modify the transaction after signing.

---

## Chapter 5: Security Considerations

### What the Coordinator Knows
- All public keys (xpubs)
- All addresses
- Transaction history
- UTXO set

### What the Coordinator DOESN'T Know
- Any private key (xprv)
- Cannot create valid signatures
- Cannot spend funds alone

### What Each Signer Knows
- Only their own private key
- The PSBT they're signing
- The destination address (they should verify!)

### Attack Vectors to Consider

**1. Address Substitution Attack**
```
Attacker compromises Coordinator, changes destination address.
Mitigation: Signers MUST verify destination on hardware wallet display.
```

**2. Fee Manipulation Attack**
```
Attacker shows wrong UTXO amount, making fees appear lower.
Mitigation: SegWit signatures commit to amount. Hardware wallets verify.
```

**3. Change Address Attack**
```
Attacker sends change to their address instead of ours.
Mitigation: Signers verify change address derivation path.
```

---

## Chapter 6: Code Implementation

### Rust PSBT Creation Flow

```rust
// Pseudocode for creating a 2-of-3 PSBT

// 1. Load the 3 xpubs and build descriptor
let descriptor = format!(
    "wsh(sortedmulti(2,{},{},{}))",
    "[fp_a/48'/1'/0'/2']xpub_a",
    "[fp_b/48'/1'/0'/2']xpub_b",
    "[fp_c/48'/1'/0'/2']xpub_c"
);

// 2. Derive the address at index 0
let address = derive_address(&descriptor, 0);

// 3. Create unsigned transaction
let tx = Transaction {
    inputs: vec![TxIn { 
        previous_output: utxo_outpoint,
        ..
    }],
    outputs: vec![TxOut {
        value: amount,
        script_pubkey: destination.script_pubkey(),
    }],
};

// 4. Build PSBT with metadata
let mut psbt = Psbt::from_unsigned_tx(tx)?;

// 5. Add witness UTXO (amount + script)
psbt.inputs[0].witness_utxo = Some(utxo);

// 6. Add witness script
psbt.inputs[0].witness_script = Some(witness_script);

// 7. Add BIP 32 derivation for all 3 keys
for (pubkey, (fingerprint, path)) in derivations {
    psbt.inputs[0].bip32_derivation.insert(pubkey, (fingerprint, path));
}

// 8. Serialize to base64
let psbt_base64 = base64::encode(psbt.serialize());
```

---

## Summary: PSBT Mental Model

```
┌─────────────────────────────────────────────────────────────────┐
│                    PSBT = ENVELOPE                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Contains: "Here's what I want to do"                         │
│             (unsigned transaction)                              │
│                                                                 │
│   Contains: "Here's what you need to know"                     │
│             (UTXOs, scripts, amounts)                          │
│                                                                 │
│   Contains: "Here's how to find your key"                      │
│             (fingerprint → derivation path)                    │
│                                                                 │
│   Collects: "Here are the approvals so far"                    │
│             (partial signatures)                               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

PSBTs are the universal language for multi-party transaction signing. Master them and you've mastered the core of Bitcoin custody.

---

## Next: Part 4 - Role Separation Architecture
In Part 4, we implement the Coordinator and Signer as separate binaries with strict security boundaries.
