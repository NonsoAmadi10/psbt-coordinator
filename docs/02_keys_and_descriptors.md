# Building Bitcoin Custody Infrastructure: Part 2 - HD Keys & Descriptors

## What You Will Learn
- BIP 32: Hierarchical Deterministic Wallets
- BIP 39: Mnemonic Seed Phrases
- BIP 48: Multisig Derivation Paths
- Output Descriptors: The modern way to define wallets

---

## Chapter 1: The Problem with Key Management

### Naive Approach: One Key Per Address
In early Bitcoin, each address had its own random key:
```
Address 1 → Random Key 1
Address 2 → Random Key 2
Address 3 → Random Key 3
...
```

**Problems:**
1. Must backup every new key
2. Key reuse for privacy = bad
3. No structure for recovery

### HD Wallets: One Seed, Infinite Keys
**BIP 32** introduced Hierarchical Deterministic wallets:

```
                    ┌──────────────┐
                    │  Master Seed │
                    │  (256 bits)  │
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
              ▼            ▼            ▼
         ┌────────┐   ┌────────┐   ┌────────┐
         │ Child  │   │ Child  │   │ Child  │
         │ Key 0  │   │ Key 1  │   │ Key 2  │
         └───┬────┘   └───┬────┘   └───┬────┘
             │            │            │
         ┌───┴───┐    ┌───┴───┐    ┌───┴───┐
         │       │    │       │    │       │
         ▼       ▼    ▼       ▼    ▼       ▼
       Key     Key  Key     Key  Key     Key
       0/0     0/1  1/0     1/1  2/0     2/1
```

**One backup, infinite addresses.**

---

## Chapter 2: The Mathematics of Key Derivation

### Extended Keys (Xprv / Xpub)

An **Extended Key** contains:
```
┌─────────────────────────────────────────────────────────────┐
│                    Extended Private Key                     │
├─────────────────────────────────────────────────────────────┤
│  Private Key (k)  │  Chain Code (c)  │  Depth  │  Parent FP │
│     256 bits      │    256 bits      │  8 bits │   32 bits  │
└─────────────────────────────────────────────────────────────┘
```

- **Private Key (k)**: The actual secret
- **Chain Code (c)**: Entropy for child derivation
- **Depth**: How deep in the tree (0 = master)
- **Parent Fingerprint**: First 4 bytes of parent's key hash

### Child Key Derivation

Given parent extended private key (kₚ, cₚ), derive child at index i:

**Normal Derivation (i < 2³¹):**
```
data = SerP(point(kₚ)) || ser32(i)
I = HMAC-SHA512(key=cₚ, data=data)
kᵢ = parse256(I_L) + kₚ  (mod n)
cᵢ = I_R
```

**Hardened Derivation (i ≥ 2³¹):**
```
data = 0x00 || ser256(kₚ) || ser32(i)
I = HMAC-SHA512(key=cₚ, data=data)
kᵢ = parse256(I_L) + kₚ  (mod n)
cᵢ = I_R
```

**Why Hardened?**
- Normal: Child public keys can be derived from parent public key
- Hardened: Requires the private key (more secure for account separation)

Notation: 
- `0` = normal child 0
- `0'` or `0h` = hardened child 0

---

## Chapter 3: Derivation Paths

### Path Notation
A derivation path describes the tree traversal:

```
m / purpose' / coin_type' / account' / change / address_index
```

Example: `m/48'/0'/0'/2'/0/5`
- `m`: Master key
- `48'`: BIP 48 purpose (multisig)
- `0'`: Bitcoin mainnet
- `0'`: Account 0
- `2'`: Script type (P2WSH)
- `0`: External chain (not change)
- `5`: Address index 5

### BIP 48: Multisig Standard

For multisig wallets, use BIP 48:

```
m / 48' / coin_type' / account' / script_type'
```

Script types:
- `1'` = P2SH-P2WSH (legacy wrapped SegWit)
- `2'` = P2WSH (native SegWit) ← **We use this**

**For our 2-of-3 on testnet/regtest:**
```
m/48'/1'/0'/2'
```
- `48'`: Multisig purpose
- `1'`: Testnet/Regtest
- `0'`: First account
- `2'`: Native SegWit (P2WSH)

---

## Chapter 4: Master Fingerprint

### What is a Fingerprint?
The fingerprint is the first 4 bytes of the HASH160 of the master public key:

```
fingerprint = HASH160(master_public_key)[0:4]
         = RIPEMD160(SHA256(master_public_key))[0:4]
```

### Why It Matters
In PSBTs, we include origin information:
```
[fingerprint/derivation_path]xpub...
```

Example:
```
[d34db33f/48'/1'/0'/2']tpubDCj...
```

When a hardware wallet sees this PSBT:
1. It checks: "Is `d34db33f` MY fingerprint?"
2. If yes, it derives the key at path `m/48'/1'/0'/2'`
3. It uses that key to sign

**This is how PSBTs enable offline signing without revealing which device is which.**

---

## Chapter 5: Output Descriptors

### The Problem with Addresses
An address alone doesn't tell you:
- How many signatures needed
- What public keys are involved
- What derivation paths to use
- What script type (P2PKH, P2SH, P2WSH, etc.)

### Output Descriptors: The Solution
A descriptor is a string that completely describes a wallet's spending conditions.

### Descriptor Syntax

**Single Key (P2WPKH):**
```
wpkh([fingerprint/path]xpub/change/*)
```

**2-of-3 Multisig (P2WSH):**
```
wsh(sortedmulti(2,
  [fp_a/48'/1'/0'/2']xpub_a/<0;1>/*,
  [fp_b/48'/1'/0'/2']xpub_b/<0;1>/*,
  [fp_c/48'/1'/0'/2']xpub_c/<0;1>/*
))
```

**Breaking it down:**
- `wsh(...)`: Wrap in Witness Script Hash (P2WSH)
- `sortedmulti(2, ...)`: 2-of-N, keys sorted lexicographically
- `[fp/path]`: Origin info (fingerprint + derivation)
- `xpub`: Extended public key at that derivation
- `<0;1>`: Either 0 (external) or 1 (change)
- `/*`: Wildcard for address index

### Why sortedmulti?
Keys in `OP_CHECKMULTISIG` must be in a consistent order. `sortedmulti` sorts keys by their public key bytes, ensuring the same script regardless of the order you list them.

---

## Chapter 6: Putting It Together

### The Complete Picture

```
┌─────────────────────────────────────────────────────────────────┐
│                        SIGNER A (CEO)                           │
├─────────────────────────────────────────────────────────────────┤
│  Seed: "abandon abandon ... about"                              │
│  Master: tprv8ZgxMBicQ...                                       │
│  Fingerprint: aabbccdd                                          │
│  Derived at m/48'/1'/0'/2':                                     │
│    xprv: tprv8gR... (SECRET - stays on device)                  │
│    xpub: tpub6D... (SHARED with coordinator)                    │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                        SIGNER B (CFO)                           │
├─────────────────────────────────────────────────────────────────┤
│  Seed: "zoo zoo ... wrong"                                      │
│  Master: tprv8YaMF...                                           │
│  Fingerprint: 11223344                                          │
│  Derived at m/48'/1'/0'/2':                                     │
│    xprv: tprv8fJ... (SECRET)                                    │
│    xpub: tpub6B... (SHARED)                                     │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                      SIGNER C (Cold Storage)                    │
├─────────────────────────────────────────────────────────────────┤
│  Seed: "legal winner ... vote"                                  │
│  Master: tprv8Xm2P...                                           │
│  Fingerprint: deadbeef                                          │
│  Derived at m/48'/1'/0'/2':                                     │
│    xprv: tprv8kL... (SECRET)                                    │
│    xpub: tpub6J... (SHARED)                                     │
└─────────────────────────────────────────────────────────────────┘

                              │
                              ▼

┌─────────────────────────────────────────────────────────────────┐
│                        COORDINATOR                              │
├─────────────────────────────────────────────────────────────────┤
│  Receives: 3 xpubs + fingerprints                               │
│  Creates Descriptor:                                            │
│                                                                 │
│  wsh(sortedmulti(2,                                             │
│    [aabbccdd/48'/1'/0'/2']tpub6D.../0/*,                        │
│    [11223344/48'/1'/0'/2']tpub6B.../0/*,                        │
│    [deadbeef/48'/1'/0'/2']tpub6J.../0/*                         │
│  ))                                                             │
│                                                                 │
│  Derives addresses, creates PSBTs                               │
│  NEVER has access to private keys                               │
└─────────────────────────────────────────────────────────────────┘
```

---

## Next: Part 3 - PSBT Construction
In Part 3, we'll implement the key generation in Rust and create our first PSBT.
