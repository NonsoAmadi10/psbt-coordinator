# Building Bitcoin Custody Infrastructure: Part 5 - PSBT Combining & Finalization

## What You Will Learn
- How to merge partial signatures from multiple signers
- Constructing the final witness stack
- Finalizing PSBTs for broadcast
- Extracting and broadcasting transactions

---

## Chapter 1: The Combining Problem

### Multiple Signers, Multiple PSBTs

After distributing the unsigned PSBT, each signer returns a version with their signature:

```
                         UNSIGNED PSBT
                              │
              ┌───────────────┼───────────────┐
              │               │               │
              ▼               ▼               ▼
        ┌──────────┐   ┌──────────┐   ┌──────────┐
        │ Signer A │   │ Signer B │   │ Signer C │
        │ (signs)  │   │ (signs)  │   │ (offline)│
        └────┬─────┘   └────┬─────┘   └──────────┘
             │               │
             ▼               ▼
        ┌──────────┐   ┌──────────┐
        │ PSBT +   │   │ PSBT +   │
        │ sig_a    │   │ sig_b    │
        └────┬─────┘   └────┬─────┘
             │               │
             └───────┬───────┘
                     │
                     ▼
              ┌──────────────┐
              │  COMBINED    │
              │  PSBT with   │
              │  sig_a +     │
              │  sig_b       │
              └──────────────┘
```

### The Combining Algorithm

PSBT combining is straightforward:
1. Start with any signed PSBT as the base
2. For each other signed PSBT:
   - For each input:
     - Merge `partial_sigs` into the base
3. Validate we have enough signatures (M of N)

```rust
// Pseudocode for combining
fn combine_psbts(psbts: Vec<Psbt>) -> Psbt {
    let mut combined = psbts[0].clone();
    
    for other_psbt in &psbts[1..] {
        for (i, input) in other_psbt.inputs.iter().enumerate() {
            // Merge partial signatures
            for (pubkey, sig) in &input.partial_sigs {
                combined.inputs[i].partial_sigs.insert(*pubkey, *sig);
            }
        }
    }
    
    combined
}
```

### What Gets Preserved

When combining PSBTs, keep:
- All `partial_sigs` from all PSBTs
- The `witness_utxo` (needed for finalization)
- The `witness_script` (needed for finalization)
- The `bip32_derivation` (for verification)

---

## Chapter 2: Signature Verification

### Before Finalizing, Verify

Never finalize a PSBT without verifying signatures:

```
┌─────────────────────────────────────────────────────────────────┐
│                   VERIFICATION CHECKLIST                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  □ Each partial_sig corresponds to a pubkey in the script      │
│  □ Each signature is valid ECDSA for the sighash               │
│  □ We have at least M signatures (2 for 2-of-3)                │
│  □ Signatures use correct sighash type (SIGHASH_ALL)           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Signature Format

Each partial signature in the PSBT has the format:
```
<ECDSA signature bytes><sighash_type byte>
```

For SIGHASH_ALL, the sighash byte is `0x01`.

The ECDSA signature itself is DER-encoded:
```
30 <total_len>
  02 <r_len> <r_bytes>
  02 <s_len> <s_bytes>
01  ← SIGHASH_ALL
```

---

## Chapter 3: The Finalization Process

### From PSBT to Transaction

Finalization transforms the PSBT metadata into actual transaction witness data:

```
BEFORE (PSBT):
┌─────────────────────────────────────────────────────────────────┐
│  Input 0:                                                        │
│    witness_utxo: TxOut { value, script_pubkey }                 │
│    witness_script: OP_2 <pk_a> <pk_b> <pk_c> OP_3 OP_CHECKMULTISIG │
│    partial_sigs: {                                               │
│      pk_a → sig_a,                                               │
│      pk_b → sig_b                                                │
│    }                                                             │
│    final_script_witness: None                                    │
└─────────────────────────────────────────────────────────────────┘

AFTER (Finalized):
┌─────────────────────────────────────────────────────────────────┐
│  Input 0:                                                        │
│    witness_utxo: None (cleared)                                  │
│    witness_script: None (cleared)                                │
│    partial_sigs: {} (cleared)                                    │
│    final_script_witness: [                                       │
│      <empty>,           ← CHECKMULTISIG dummy                   │
│      <sig_a>,           ← First signature                       │
│      <sig_b>,           ← Second signature                      │
│      <witness_script>   ← The actual script                     │
│    ]                                                             │
└─────────────────────────────────────────────────────────────────┘
```

### Witness Stack Construction

For P2WSH 2-of-3 multisig, the witness stack is:
```
Stack (bottom to top):
┌────────────────────────────────────────┐
│ <witness_script>                       │  ← Item 4: The script itself
├────────────────────────────────────────┤
│ <sig_2>                                │  ← Item 3: Second signature
├────────────────────────────────────────┤
│ <sig_1>                                │  ← Item 2: First signature
├────────────────────────────────────────┤
│ <empty>                                │  ← Item 1: Dummy (CHECKMULTISIG bug)
└────────────────────────────────────────┘
```

### Signature Ordering

**CRITICAL**: Signatures must be in the same order as public keys in the script.

For `sortedmulti`, keys are sorted lexicographically by their serialized bytes. The signatures must match this order.

```rust
// Sort signatures by their corresponding public key
let mut sigs: Vec<_> = partial_sigs.iter().collect();
sigs.sort_by(|a, b| a.0.serialize().cmp(&b.0.serialize()));

// Take first M signatures
let selected: Vec<_> = sigs.into_iter().take(threshold).collect();
```

---

## Chapter 4: The CHECKMULTISIG Bug

### History Lesson

The original `OP_CHECKMULTISIG` implementation has an off-by-one bug. It pops one extra item from the stack than it should.

This bug has existed since Bitcoin's creation and is now part of consensus rules. Every multisig transaction must include a dummy element.

```
What CHECKMULTISIG expects:
  <dummy> <sig_1> <sig_2> ... <m> <pk_1> <pk_2> ... <n> OP_CHECKMULTISIG

The <dummy> is consumed but ignored.
```

### In Our Code

```rust
// Build witness - note the empty element first!
let mut witness = Witness::new();

// Push empty dummy (required by CHECKMULTISIG bug)
witness.push([]);

// Push signatures in order
for (_, sig) in selected_sigs {
    witness.push(sig.serialize());
}

// Push the witness script
witness.push(witness_script.as_bytes());
```

---

## Chapter 5: Transaction Extraction

### From Finalized PSBT to Transaction

Once finalized, we extract the transaction:

```rust
// Extract the final signed transaction
let final_tx = psbt.extract_tx()?;

// The transaction is now complete:
// - Inputs have witness data populated
// - Ready for broadcast

// Serialize to hex for bitcoin-cli
let tx_hex = bitcoin::consensus::encode::serialize_hex(&final_tx);
```

### Transaction Properties

The extracted transaction should have:
```
┌─────────────────────────────────────────────────────────────────┐
│  Transaction Summary                                             │
├─────────────────────────────────────────────────────────────────┤
│  TXID: a1b2c3...                                                │
│  Size: 254 bytes (raw)                                          │
│  vSize: 142 vbytes (weight/4)                                   │
│  Weight: 566 WU                                                 │
│                                                                 │
│  Inputs:                                                        │
│    [0] prev_txid:0                                              │
│        Witness: <dummy> <sig_a> <sig_b> <script>                │
│                                                                 │
│  Outputs:                                                       │
│    [0] 0.50000000 BTC → bc1q...destination                     │
│    [1] 0.49999000 BTC → bc1q...change                          │
│                                                                 │
│  Fee: 0.00001000 BTC (1000 sats)                               │
│  Fee Rate: ~7 sat/vB                                            │
└─────────────────────────────────────────────────────────────────┘
```

---

## Chapter 6: Broadcasting

### Methods to Broadcast

**1. Bitcoin Core RPC**
```bash
bitcoin-cli sendrawtransaction <tx_hex>
```

**2. Electrum Server**
```python
import socket
s = socket.create_connection(('electrum.server.com', 50002))
s.send(b'blockchain.transaction.broadcast\n<tx_hex>\n')
```

**3. Block Explorer APIs**
```bash
curl -X POST https://blockstream.info/api/tx -d '<tx_hex>'
```

**4. Direct P2P**
Connect to Bitcoin P2P network and send `tx` message.

### Monitoring Confirmation

After broadcast:
1. Transaction enters mempool
2. Miners include it in a block
3. Block is mined and propagated
4. More blocks confirm it

```bash
# Check transaction status
bitcoin-cli gettransaction <txid>

# Get raw transaction with confirmations
bitcoin-cli getrawtransaction <txid> true
```

---

## Chapter 7: Complete Code Flow

### The Finalizer Implementation

```rust
fn finalize_psbt(mut psbt: Psbt) -> Result<Psbt, Error> {
    for input_index in 0..psbt.inputs.len() {
        let input = &psbt.inputs[input_index];
        
        // 1. Get witness script
        let witness_script = input.witness_script
            .as_ref()
            .ok_or("Missing witness script")?
            .clone();
        
        // 2. Sort signatures by pubkey (for sortedmulti)
        let mut sigs: Vec<_> = input.partial_sigs.iter().collect();
        sigs.sort_by(|a, b| a.0.serialize().cmp(&b.0.serialize()));
        
        // 3. Take first M signatures
        let selected: Vec<_> = sigs.into_iter().take(2).collect();
        
        // 4. Build witness stack
        let mut witness = Witness::new();
        witness.push([]);  // CHECKMULTISIG dummy
        for (_, sig) in &selected {
            witness.push(sig.serialize());
        }
        witness.push(witness_script.as_bytes());
        
        // 5. Set final witness
        psbt.inputs[input_index].final_script_witness = Some(witness);
        
        // 6. Clear PSBT-only fields
        psbt.inputs[input_index].partial_sigs.clear();
        psbt.inputs[input_index].bip32_derivation.clear();
        psbt.inputs[input_index].witness_script = None;
        psbt.inputs[input_index].witness_utxo = None;
    }
    
    Ok(psbt)
}
```

---

## Chapter 8: Error Handling

### Common Finalization Errors

| Error | Cause | Solution |
|-------|-------|----------|
| Insufficient signatures | Less than M sigs | Get more signers to sign |
| Invalid signature | Wrong key or data | Re-sign with correct key |
| Missing witness script | PSBT incomplete | Add script during creation |
| Missing witness UTXO | PSBT incomplete | Add UTXO during creation |
| Wrong signature order | sortedmulti mismatch | Sort by pubkey before building |

### Defensive Programming

```rust
// Always verify before finalizing
fn verify_ready_to_finalize(psbt: &Psbt, threshold: usize) -> Result<(), Error> {
    for (i, input) in psbt.inputs.iter().enumerate() {
        // Check witness script present
        if input.witness_script.is_none() {
            return Err(format!("Input {} missing witness script", i).into());
        }
        
        // Check sufficient signatures
        if input.partial_sigs.len() < threshold {
            return Err(format!(
                "Input {} has {} sigs, need {}", 
                i, input.partial_sigs.len(), threshold
            ).into());
        }
    }
    Ok(())
}
```

---

## Summary: The Complete Lifecycle

```
┌─────────────────────────────────────────────────────────────────┐
│                    PSBT LIFECYCLE                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. CREATE (Coordinator)                                        │
│     • Build unsigned TX                                         │
│     • Add UTXO + script + derivations                          │
│     • Output: unsigned.psbt                                     │
│                                                                 │
│  2. SIGN (Each Signer)                                          │
│     • Find own key by fingerprint                               │
│     • Verify transaction details                                │
│     • Add partial_sig                                           │
│     • Output: signed_X.psbt                                     │
│                                                                 │
│  3. COMBINE (Coordinator)                                       │
│     • Merge all partial_sigs                                    │
│     • Verify M signatures present                               │
│     • Output: combined.psbt                                     │
│                                                                 │
│  4. FINALIZE (Coordinator)                                      │
│     • Build witness stack                                       │
│     • Order signatures correctly                                │
│     • Clear PSBT metadata                                       │
│     • Output: finalized.psbt                                    │
│                                                                 │
│  5. EXTRACT (Coordinator)                                       │
│     • Get signed Transaction                                    │
│     • Output: final_tx.hex                                      │
│                                                                 │
│  6. BROADCAST                                                   │
│     • Submit to Bitcoin network                                 │
│     • Monitor for confirmation                                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

You've now completed the core PSBT workflow. In Part 6, we'll test everything end-to-end with Bitcoin Core regtest.

---

## Next: Part 6 - Testing with Bitcoin Core Regtest
We'll set up a local Bitcoin network and test real transactions from creation to confirmation.
