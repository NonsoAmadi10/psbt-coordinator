# Building Bitcoin Custody Infrastructure: Part 4 - Role Separation

## What You Will Learn
- The Coordinator/Signer architecture
- Security boundaries and trust assumptions
- Why separation of concerns is critical for custody
- Practical implementation patterns

---

## Chapter 1: The Fundamental Principle

### The Golden Rule of Custody

> **No single component should be able to spend funds unilaterally.**

This means:
- The **Coordinator** knows all public keys but zero private keys
- Each **Signer** knows only its own private key
- Spending requires cooperation from multiple parties

```
┌─────────────────────────────────────────────────────────────────┐
│                    SECURITY ARCHITECTURE                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   COORDINATOR (Hot/Online)                                      │
│   ═══════════════════════                                       │
│   • Knows: All 3 xpubs                                          │
│   • Creates: Unsigned PSBTs                                     │
│   • Combines: Partial signatures                                │
│   • Broadcasts: Final transactions                              │
│   • CANNOT: Create valid signatures                             │
│                                                                 │
│   ─────────────────────────────────────────────────────────     │
│                                                                 │
│   SIGNER A (Cold)      SIGNER B (Cold)      SIGNER C (Cold)    │
│   ═══════════════      ═══════════════      ═══════════════    │
│   • Knows: xprv_a      • Knows: xprv_b      • Knows: xprv_c    │
│   • Signs: With A      • Signs: With B      • Signs: With C    │
│   • Verifies: TX       • Verifies: TX       • Verifies: TX     │
│   • CANNOT: See        • CANNOT: See        • CANNOT: See      │
│     other keys           other keys           other keys       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Chapter 2: The Coordinator Role

### What the Coordinator Does

The Coordinator is the "brain" of the operation. It:

1. **Manages the wallet descriptor** - Stores all xpubs and derives addresses
2. **Monitors the blockchain** - Tracks UTXOs and balances
3. **Creates transactions** - Builds unsigned PSBTs with all metadata
4. **Distributes PSBTs** - Sends to signers for approval
5. **Combines signatures** - Merges partial_sigs from each signer
6. **Finalizes and broadcasts** - Creates the final TX and submits to network

### What the Coordinator CANNOT Do

- Sign any transaction
- Spend any funds
- Access any private key
- Create forged signatures

### Coordinator Trust Assumptions

The Coordinator is **NOT trusted** with funds, but IS trusted to:
- Show correct transaction amounts (signers must verify!)
- Not substitute destination addresses (signers must verify!)
- Not leak transaction privacy (knows all addresses)

**Attack: Coordinator Compromise**
If an attacker controls the Coordinator, they can:
- Create transactions to attacker's address
- BUT they still need 2/3 signers to approve
- Defense: Signers ALWAYS verify destination address on their device

---

## Chapter 3: The Signer Role

### What Each Signer Does

A Signer is a single key holder. It:

1. **Receives PSBTs** - Gets unsigned/partially-signed PSBTs
2. **Parses and validates** - Extracts transaction details
3. **Displays for verification** - Shows amount, destination, fee
4. **Finds its key** - Scans BIP32 derivations for its fingerprint
5. **Signs if approved** - Creates ECDSA signature
6. **Returns signed PSBT** - Adds partial_sig and returns

### Signer Display Requirements

A secure signer MUST display:
```
┌─────────────────────────────────────────────────────────────────┐
│                    VERIFY BEFORE SIGNING                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   SENDING:  0.50000000 BTC                                      │
│   TO:       bc1q...recipient...                                 │
│   FEE:      0.00001000 BTC                                      │
│                                                                 │
│   ┌─────────────────────────────────────────────────────────┐  │
│   │  Is this the correct recipient address?                  │  │
│   │  Verify independently (phone, paper, other channel)      │  │
│   └─────────────────────────────────────────────────────────┘  │
│                                                                 │
│              [ APPROVE ]        [ REJECT ]                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Signer Trust Assumptions

Each Signer IS trusted with:
- Securely storing its private key
- Verifying transaction details before signing
- Not signing blindly

Each Signer is NOT trusted with:
- Other signers' keys (doesn't know them)
- Creating complete transactions alone

---

## Chapter 4: Information Flow

### The Complete Transaction Flow

```
                           TRANSACTION LIFECYCLE
  
  ┌──────────────────────────────────────────────────────────────────┐
  │                                                                  │
  │  [1] INITIATION                                                  │
  │      Coordinator receives withdrawal request                     │
  │      - Destination address                                       │
  │      - Amount                                                    │
  │                                                                  │
  └──────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │                                                                  │
  │  [2] PSBT CREATION (Coordinator)                                 │
  │      - Select UTXOs                                              │
  │      - Build unsigned TX                                         │
  │      - Add witness UTXO, script, derivation paths               │
  │      - Export as base64                                          │
  │                                                                  │
  │      Output: unsigned.psbt                                       │
  │                                                                  │
  └──────────────────────────────────────────────────────────────────┘
                                  │
                   ┌──────────────┴──────────────┐
                   │                             │
                   ▼                             ▼
  ┌────────────────────────────┐   ┌────────────────────────────┐
  │                            │   │                            │
  │  [3] SIGNING (Signer A)    │   │  [4] SIGNING (Signer B)    │
  │      - Import PSBT         │   │      - Import PSBT         │
  │      - Verify TX details   │   │      - Verify TX details   │
  │      - Find own key        │   │      - Find own key        │
  │      - Create signature    │   │      - Create signature    │
  │      - Export signed PSBT  │   │      - Export signed PSBT  │
  │                            │   │                            │
  │  Output: signed_a.psbt     │   │  Output: signed_b.psbt     │
  │                            │   │                            │
  └────────────────────────────┘   └────────────────────────────┘
                   │                             │
                   └──────────────┬──────────────┘
                                  │
                                  ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │                                                                  │
  │  [5] COMBINING (Coordinator)                                     │
  │      - Import all signed PSBTs                                   │
  │      - Merge partial_sigs into one PSBT                         │
  │      - Verify 2/3 signatures present                            │
  │                                                                  │
  │      Output: combined.psbt                                       │
  │                                                                  │
  └──────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │                                                                  │
  │  [6] FINALIZATION (Coordinator)                                  │
  │      - Build witness stack                                       │
  │      - Clear PSBT metadata                                       │
  │      - Extract signed TX                                         │
  │                                                                  │
  │      Output: final_tx.hex                                        │
  │                                                                  │
  └──────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │                                                                  │
  │  [7] BROADCAST                                                   │
  │      - Submit to Bitcoin network                                 │
  │      - Monitor for confirmation                                  │
  │                                                                  │
  └──────────────────────────────────────────────────────────────────┘
```

---

## Chapter 5: Security Boundaries

### Defense in Depth

```
┌─────────────────────────────────────────────────────────────────┐
│                     SECURITY LAYERS                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Layer 1: CRYPTOGRAPHIC                                         │
│  ─────────────────────                                          │
│  • Multisig requires M of N                                     │
│  • Private keys never leave signers                             │
│  • SegWit commits to amounts (no fee attacks)                   │
│                                                                 │
│  Layer 2: ARCHITECTURAL                                         │
│  ──────────────────────                                         │
│  • Coordinator has NO private keys                              │
│  • Signers are air-gapped/isolated                              │
│  • Different personnel control different keys                   │
│                                                                 │
│  Layer 3: PHYSICAL                                              │
│  ─────────────────                                              │
│  • Keys in different geographic locations                       │
│  • Hardware Security Modules (HSMs)                             │
│  • Vault storage for backup seeds                               │
│                                                                 │
│  Layer 4: PROCEDURAL                                            │
│  ──────────────────                                             │
│  • Dual control (two people for sensitive ops)                  │
│  • Time delays for large withdrawals                            │
│  • Out-of-band verification (phone call to confirm)             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### The $5 Wrench Attack

Cryptography is impervious. Humans are not.

```
  "I have $1M in Bitcoin secured by 2-of-3 multisig"
  
  Attacker: *threatens with $5 wrench*
  
  Response Options:
  
  1. DURESS CODE
     - Signer provides a "duress wallet" that has small amount
     - Attacker thinks they succeeded
  
  2. TIME LOCK
     - Transactions require 48-hour delay
     - Cannot be bypassed even with keys
     - "I can't give you the money for 48 hours"
  
  3. GEOGRAPHIC DISTRIBUTION
     - "The other keys are in Switzerland and Singapore"
     - "I physically cannot access them"
  
  4. CORPORATE STRUCTURE
     - No single person can authorize withdrawal
     - Board approval required > $X
```

---

## Chapter 6: Implementation Details

### Our Binary Structure

```
psbt-coordinator/
├── src/
│   ├── lib.rs          # Shared types (MultisigWallet, KeyData)
│   ├── main.rs         # Entry point
│   └── bin/
│       ├── keygen.rs       # Generate 3 key pairs
│       ├── coordinator.rs  # Create and combine PSBTs
│       ├── signer.rs       # Sign with individual key
│       └── finalizer.rs    # Finalize and broadcast
```

### Running the Full Workflow

```bash
# 1. Generate keys (one-time setup)
cargo run --bin keygen

# 2. Create unsigned PSBT (Coordinator)
cargo run --bin coordinator

# 3. Sign with first key (Signer A)
cargo run --bin signer -- key_a.json unsigned.psbt.base64

# 4. Sign with second key (Signer B)
cargo run --bin signer -- key_b.json signed_by_key_a.psbt.base64

# 5. Finalize (Coordinator)
cargo run --bin finalizer -- signed_by_key_b.psbt.base64

# 6. Broadcast (requires Bitcoin Core)
bitcoin-cli -regtest sendrawtransaction $(cat final_tx.hex)
```

---

## Chapter 7: Production Considerations

### Coordinator Deployment

In production, the Coordinator is typically:
- A server/service
- Behind authentication (admin portal)
- Connected to a Bitcoin node
- Has rate limiting and approval workflows
- Logs all operations for audit

### Signer Deployment Options

**Option 1: Hardware Wallets**
- Ledger, Trezor, Coldcard
- Key never leaves secure element
- User physically approves each TX

**Option 2: HSM (Hardware Security Module)**
- Thales, AWS CloudHSM, Azure Dedicated HSM
- Enterprise-grade key protection
- Policy enforcement in hardware

**Option 3: Air-Gapped Computers**
- Never connected to internet
- PSBT transferred via QR code or USB
- Maximum isolation

**Option 4: MPC (Multi-Party Computation)**
- Key shares distributed across nodes
- Signatures computed jointly
- No single point of failure

---

## Summary: The Trust Model

```
┌─────────────────────────────────────────────────────────────────┐
│                    WHO TRUSTS WHOM?                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Coordinator trusts:                                            │
│    ✗ Nobody - it has no secrets                                │
│                                                                 │
│  Signers trust:                                                 │
│    ✗ Not the Coordinator (verify everything)                   │
│    ✗ Not other Signers (don't share keys)                      │
│    ✓ Only themselves (their own verification)                  │
│                                                                 │
│  The System trusts:                                             │
│    ✓ Math (ECDSA, SHA256, secp256k1)                           │
│    ✓ Protocol (Bitcoin consensus rules)                        │
│    ✓ That attackers can't compromise M signers                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

Role separation isn't just good practice—it's the foundation of Bitcoin custody security. Without it, you're just one hack away from losing everything.

---

## Next: Part 5 - PSBT Combining and Finalization
In Part 5, we implement the combiner and finalizer, completing the transaction lifecycle.
