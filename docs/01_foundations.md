# Building Bitcoin Custody Infrastructure: Part 1 - Foundations

## What You Will Learn
This series teaches you to build production-grade Bitcoin custody software. By the end, you'll understand:
- Elliptic curve cryptography fundamentals
- HD wallets and key derivation
- 2-of-3 multisig architecture
- PSBT creation, signing, and combining
- Role separation for institutional security

---

## Chapter 1: Elliptic Curve Cryptography (ECC)

### The Mathematical Foundation
Bitcoin uses the **secp256k1** elliptic curve. The equation is:

```
y² = x³ + 7  (mod p)
```

Where `p` is a very large prime number (2²⁵⁶ - 2³² - 977).

### Key Concepts

**Private Key (k):**
- A random 256-bit number
- Must be in range [1, n-1] where n is the curve order
- This is your SECRET - never share it

```
k ∈ {1, 2, 3, ..., n-1}
n ≈ 1.158 × 10⁷⁷
```

**Public Key (P):**
- A point on the elliptic curve
- Derived by "multiplying" the generator point G by k

```
P = k × G
```

This is NOT regular multiplication - it's elliptic curve point multiplication (repeated point addition).

**The Security Guarantee (Discrete Logarithm Problem):**
- Given P and G, it's computationally infeasible to find k
- This is what makes Bitcoin secure

### Visualization

```
       P = k × G
       
    Private Key (k)          Public Key (P)
    ──────────────           ──────────────
    256-bit secret    →→→    Point on curve
    (your password)          (your address)
    
    EASY: k → P
    IMPOSSIBLE: P → k
```

---

## Chapter 2: The Problem with Single-Key Wallets

### Single Signature (1-of-1)
A standard Bitcoin wallet uses ONE private key.

```
┌─────────────────┐
│   Private Key   │  ←── Single point of failure
│      (k)        │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Public Key    │
│      (P)        │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│    Address      │
│  bc1q...        │
└─────────────────┘
```

**Problems:**
1. **Key Loss = Fund Loss**: If you lose the key, funds are gone forever
2. **Key Theft = Fund Theft**: If someone copies your key, they steal everything
3. **No Redundancy**: No backup mechanism built-in

### The $100M Problem
Imagine you're a Bitcoin custody company holding $100M in customer funds.
- Can you trust ONE person with the key?
- Can you trust ONE computer with the key?
- Can you trust ONE location with the key?

**The answer is NO.** This is why we need **multisig**.

---

## Chapter 3: Multisig - The Solution

### What is M-of-N Multisig?
A multisig requires **M signatures** out of **N total keys** to spend funds.

Common configurations:
- **2-of-3**: 3 keys, need any 2 (our focus)
- **3-of-5**: 5 keys, need any 3 (enterprise)
- **2-of-2**: 2 keys, need both (escrow)

### 2-of-3 Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     2-of-3 MULTISIG                         │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│   ┌─────────┐      ┌─────────┐      ┌─────────┐             │
│   │  Key A  │      │  Key B  │      │  Key C  │             │
│   │ (CEO)   │      │ (CFO)   │      │ (Cold)  │             │
│   └────┬────┘      └────┬────┘      └────┬────┘             │
│        │                │                │                   │
│        └────────────────┼────────────────┘                   │
│                         │                                    │
│                         ▼                                    │
│              ┌──────────────────┐                           │
│              │  Multisig Script │                           │
│              │   OP_2 ... OP_3  │                           │
│              │ OP_CHECKMULTISIG │                           │
│              └────────┬─────────┘                           │
│                       │                                      │
│                       ▼                                      │
│              ┌──────────────────┐                           │
│              │     Address      │                           │
│              │   bc1q...        │                           │
│              └──────────────────┘                           │
│                                                              │
│   TO SPEND: Need ANY 2 of the 3 keys to sign                │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### Security Analysis

**Redundancy (Fault Tolerance):**
- Lose Key A? Use Key B + Key C
- Lose Key B? Use Key A + Key C
- Lose Key C? Use Key A + Key B

**Theft Resistance:**
- Thief steals Key A? Can't spend (need 2 keys)
- Thief steals Key B? Can't spend (need 2 keys)
- Thief must compromise 2 separate keys = much harder

**Cost of Attack Formula:**
```
Cost(Attack) = Cost(Compromise Key 1) + Cost(Compromise Key 2)
```

If keys are in different:
- Physical locations
- Legal jurisdictions
- Hardware devices
- Organizations

...then the cost of attack increases dramatically. This is your **scarcity premium**.

---

## Chapter 4: Bitcoin Script - The Locking Mechanism

### How Bitcoin Locks Funds
Bitcoin uses a simple stack-based scripting language. Funds are "locked" by a **ScriptPubKey** and "unlocked" by a **ScriptSig** (or Witness for SegWit).

### The Multisig Script

For 2-of-3 multisig, the locking script (WitnessScript) is:

```
OP_2
<PubKey_A>   (33 bytes, compressed)
<PubKey_B>   (33 bytes, compressed)
<PubKey_C>   (33 bytes, compressed)
OP_3
OP_CHECKMULTISIG
```

**What each opcode does:**
- `OP_2`: Push the number 2 (signatures required)
- `<PubKey_X>`: Push the public key bytes
- `OP_3`: Push the number 3 (total keys)
- `OP_CHECKMULTISIG`: Verify M-of-N signatures

### Spending the Multisig (Witness Stack)

To unlock, provide:
```
<dummy>      (empty, required by CHECKMULTISIG bug)
<Sig_A>      (ECDSA signature from Key A)
<Sig_B>      (ECDSA signature from Key B)
```

The `<dummy>` is required due to an off-by-one bug in the original Bitcoin implementation. It's now part of the consensus rules.

### P2WSH: SegWit Wrapping

We don't put the raw script on-chain. Instead, we use **P2WSH** (Pay-to-Witness-Script-Hash):

```
ScriptPubKey = OP_0 <SHA256(WitnessScript)>
```

This creates a `bc1q...` address (62 characters for mainnet).

**Why P2WSH?**
1. **Smaller on-chain footprint**: Only 34 bytes in the output
2. **Lower fees**: Witness data is discounted
3. **Hiding the policy**: The spending conditions are revealed only when spending

---

## Chapter 5: Threshold Cryptography Preview

### Beyond Script-Based Multisig
The multisig we're building uses Bitcoin Script. There's a more advanced approach: **Threshold Signatures (TSS)**.

| Feature | Script Multisig | Threshold Signatures |
|---------|----------------|---------------------|
| On-chain footprint | Reveals M-of-N structure | Looks like single-sig |
| Privacy | Low (script visible) | High (indistinguishable) |
| Complexity | Simple | Complex (MPC protocols) |
| Recovery | Easy (standard tools) | Requires key shards |
| Fees | Higher (more data) | Lower (single sig) |

For institutional custody, you'll often see:
- **Script Multisig** for transparency and auditability
- **Threshold Signatures** for privacy and efficiency

We focus on Script Multisig in this series because:
1. It's the foundation (understand this first)
2. It's transparent and auditable
3. It's supported by all hardware wallets
4. It's battle-tested since 2012

---

## Next: Part 2 - Keys, Descriptors, and HD Wallets
In Part 2, we'll write Rust code to:
- Generate HD keys (BIP 32)
- Use proper derivation paths (BIP 48)
- Create output descriptors
