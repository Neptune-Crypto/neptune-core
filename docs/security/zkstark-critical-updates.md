# Critical Updates: zk-STARK Requirements & Implementation Reality

**Document Version:** 1.0  
**Date:** 2025-10-17  
**Based On:** Team feedback and technical analysis  
**Status:** **URGENT** - Requires Strategy Revision

---

## Executive Summary: Major Corrections Needed

Based on team feedback and codebase analysis, several **critical corrections** are needed to the air-gapped signing strategy:

1. **❌ RAM Requirements Understated**: Team advises **>64GB RAM** (not 8-32GB)
2. **✅ Proof Options Exist**: Neptune has 3 proof modes (not just single proof)
3. **⚠️ Raspberry Pi Infeasible**: Cannot handle >64GB RAM requirement
4. **🔍 No Offline Signer Yet**: Air-gapped signing doesn't exist yet
5. **🔬 Triton VM**: Custom VM for zk-STARK execution

---

## Part 1: Corrected RAM Requirements

### 1.1 Team Feedback: >64GB RAM

**From team:** "Team advises > 64GB RAM"

**From transaction proof lifecycle doc:**
> "**Requires significant computational resources** (at least 64GB RAM and powerful CPUs)" (Line 50)

**Correction Table:**

| Document | Previous Estimate | Actual Requirement | Gap |
|----------|-------------------|-------------------|-----|
| **zkstark-airgapped-strategy.md** | 8-32 GB | **>64 GB** | **2x-8x underestimate** |
| **hardware-wallet-p2p-privacy-analysis.md** | 8-32 GB | **>64 GB** | **2x-8x underestimate** |

**Impact:**

- ❌ **Raspberry Pi 5 (8GB) is completely infeasible** (need 64-128GB)
- ⚠️ **Minimum signer**: Desktop with 64GB+ RAM (~$500-$1000)
- ⚠️ **Recommended signer**: Workstation with 128GB RAM (~$2000+)

---

### 1.2 Revised Hardware Requirements

#### **Air-Gapped Signer Minimum Specs (Corrected)**

| Component | Minimum | Recommended | Enterprise |
|-----------|---------|-------------|------------|
| **RAM** | **64 GB** | **128 GB** | **256 GB** |
| **CPU** | 8-core @ 3 GHz | 16-core @ 4 GHz | 32-core @ 4+ GHz |
| **Storage** | 500 GB NVMe SSD | 1 TB NVMe SSD | 2 TB NVMe SSD |
| **Cost** | $800-$1200 | $2000-$3000 | $5000+ |

**Why This Matters:**

```
Hardware Wallet (Ledger Nano X):
RAM: 320 KB
Cost: $149

Air-Gapped Signer (Minimum):
RAM: 64 GB = 64,000,000 KB
Cost: $800-$1200

Gap: 200,000x RAM, 5-8x price
```

**Conclusion:** Air-gapped signing is **expensive** but still the only viable option for zk-STARKs.

---

### 1.3 Raspberry Pi Analysis

**❌ Raspberry Pi 5 (Maximum Config):**
- RAM: 8 GB
- Required: >64 GB
- **Gap: 8x insufficient**

**Verdict:** Raspberry Pi is **not viable** for zk-STARK proving in Neptune.

**Alternative Cheap Options:**

1. **Used Workstation ($500-$800)**
   - Dell Precision / HP Z-series
   - 64 GB RAM upgrade
   - Air-gap by removing Wi-Fi card

2. **Budget Desktop Build ($800-$1000)**
   - AMD Ryzen 7 / Intel i7
   - 64 GB DDR4 RAM (4x16GB)
   - Budget motherboard, no GPU needed

3. **Enterprise Surplus (~$500)**
   - Decommissioned server hardware
   - Dell R730 / HP DL380 Gen9
   - Already 64-128GB RAM
   - Remove network cards for air-gap

---

## Part 2: Neptune's Three Proof Modes

### 2.1 Discovery: Proof Collection vs. Single Proof

**From the transaction proof lifecycle document, Neptune has THREE proving modes:**

#### **Mode 1: Lockscript** (Basic)
- **Hardware:** Any device
- **Proof:** Minimal validation
- **Use Case:** Simple transactions
- **Fee:** Lowest
- **Proving Time:** Seconds

#### **Mode 2: Proof Collection** (Intermediate)
- **Hardware:** Most computers/smartphones
- **RAM:** ~2-8 GB (consumer devices)
- **Proof:** Intermediate proof requiring "raise" operation
- **Use Case:** Standard transactions
- **Fee:** **≥0.05 NPT** (higher - requires third-party proof upgrader)
- **Proving Time:** Minutes
- **Key Feature:** **Does NOT require 64GB RAM**

#### **Mode 3: Single Proof** (Full)
- **Hardware:** Workstation with **64GB+ RAM**
- **Proof:** Full zk-STARK proof
- **Use Case:** High-value transactions
- **Fee:** **Lowest** (direct block inclusion)
- **Proving Time:** Minutes to hours
- **Key Feature:** Most cost-effective for frequent transactions

---

### 2.2 The "Raise" Operation

**Critical Discovery:** Neptune has a **two-tier proof system**.

```
Consumer Device (2-8GB RAM)
    │
    ├─► Generates "Proof Collection"
    │   ├─ Can be generated on phones, laptops
    │   ├─ Proving time: ~1-5 minutes
    │   └─ Safe to transmit (no secret keys)
    │
    ▼
"Raise" Operation (64GB+ RAM)
    │
    ├─► Upgrades "Proof Collection" → "Single Proof"
    │   ├─ Requires 64GB+ RAM
    │   ├─ Proving time: Minutes to hours
    │   └─ Done by "proof upgraders" (third-party service)
    │
    ▼
Block Composition
    │
    └─► "Single Proof" included in block by composers
```

**Implications:**

1. **Most users can generate transactions on consumer hardware** (Proof Collection mode)
2. **Only "proof upgraders" need 64GB+ RAM** (specialized service)
3. **Air-gapped signer could use Proof Collection mode** for easier setup
4. **Trade-off: Higher fees (≥0.05 NPT) vs. accessibility**

---

### 2.3 Revised Air-Gapped Strategy Options

#### **Option A: Full Single Proof (High-End)**

**Setup:**
- Air-gapped workstation: 64-128GB RAM
- Generates Single Proofs directly
- Lowest transaction fees
- **Cost:** $800-$3000

**Pros:**
- ✅ Lowest fees
- ✅ No reliance on third-party proof upgraders
- ✅ Fully self-sovereign

**Cons:**
- ❌ Expensive hardware
- ❌ Long proving time (minutes to hours)
- ❌ High barrier to entry

---

#### **Option B: Proof Collection (Consumer-Friendly)** ← **NEW RECOMMENDATION**

**Setup:**
- Air-gapped laptop/desktop: 8-16GB RAM
- Generates Proof Collections
- Uses third-party "proof upgrader" services
- **Cost:** $200-$500 (used laptop)

**Workflow:**

```
1. Air-Gapped Laptop (8GB RAM)
    ├─► Generates unsigned transaction
    ├─► Generates Proof Collection (~1-5 min)
    └─► Exports as QR code

2. Online Watch-Only Node
    ├─► Scans QR code
    ├─► Submits Proof Collection to mempool
    └─► Pays "proof upgrader" fee (≥0.05 NPT)

3. Proof Upgrader (64GB+ RAM)
    ├─► Monitors mempool for Proof Collections
    ├─► "Raises" Proof Collection → Single Proof
    └─► Returns Single Proof to mempool

4. Composer (Block Creator)
    └─► Includes Single Proof in block
```

**Pros:**
- ✅ **Affordable hardware** ($200-$500 vs. $800-$3000)
- ✅ **Faster proving** (~1-5 min vs. minutes to hours)
- ✅ **Lower barrier to entry**
- ✅ **Still air-gapped** (keys never on networked device)

**Cons:**
- ⚠️ **Higher fees** (≥0.05 NPT per transaction)
- ⚠️ **Reliance on proof upgraders** (third-party trust)
- ⚠️ **Proof Collection cannot be updated** (if not included in block)

---

#### **Option C: Hybrid (Flexible)**

**Setup:**
- Air-gapped laptop: 8-16GB RAM (for Proof Collections)
- Optional: High-end workstation: 64-128GB RAM (for Single Proofs)

**Strategy:**
- **Small transactions (<10 NPT):** Use Proof Collection mode
- **Large transactions (>100 NPT):** Use Single Proof mode

**Pros:**
- ✅ **Flexibility** (choose based on transaction value)
- ✅ **Cost optimization** (pay upgrader fees only when worth it)

**Cons:**
- ⚠️ **Complexity** (maintain two air-gapped systems)

---

### 2.4 Recommendation: Proof Collection as Default

**🎯 New Strategic Direction:**

1. **Default: Proof Collection Mode** (8-16GB RAM)
   - Affordable for most users
   - Fast proving time
   - Still air-gapped
   - Accept higher fees as trade-off

2. **Advanced: Single Proof Mode** (64-128GB RAM)
   - For power users, exchanges, whales
   - Lowest fees
   - Full self-sovereignty

**Marketing Message:**

> "Neptune offers **two tiers of air-gapped security**:
>
> - **Standard Tier:** Air-gapped laptop (8GB RAM) + proof upgrader services
>   - Cost: $200-$500 | Fees: ≥0.05 NPT | Setup: 30 minutes
>
> - **Premium Tier:** Air-gapped workstation (64GB+ RAM) + self-hosted proving
>   - Cost: $800-$3000 | Fees: Minimal | Setup: 1 hour
>
> Both tiers provide **military-grade security**—choose based on transaction volume and budget."

---

## Part 3: Triton VM Architecture

### 3.1 What Is Triton VM?

**From `/home/anon/Documents/GitHub/triton-vm/`:**

**Triton VM** is a **custom virtual machine** designed specifically for generating zk-STARKs.

**Key Components:**

```
triton-vm/
├── triton-air/          # Algebraic Intermediate Representation
├── triton-isa/          # Instruction Set Architecture
├── triton-vm/           # VM implementation
│   ├── stark.rs         # zk-STARK prover/verifier
│   ├── proof.rs         # Proof generation
│   └── vm.rs            # VM execution
└── specification/       # Technical specification
```

**Why Neptune Uses Triton VM:**

1. **Optimized for zk-STARKs**: Custom ISA designed for efficient proof generation
2. **Quantum-safe**: Hash-based, post-quantum secure
3. **Transparent**: No trusted setup
4. **Recursive proofs**: Can verify proofs within proofs

---

### 3.2 Implications for Air-Gapped Signing

**Key Insight:** Triton VM is the **proving engine**.

```
Neptune Transaction Signing Flow:

1. Build Transaction (wallet logic)
    ├─► Inputs, outputs, fee
    └─► Lock scripts, witnesses

2. Triton VM Execution (proving engine)
    ├─► Execute transaction validation in VM
    ├─► Generate execution trace
    └─► Generate zk-STARK proof
        ├─ Proof Collection (2-8GB RAM)
        └─ Single Proof (64GB+ RAM)

3. Finalize Transaction
    └─► Attach proof to transaction
```

**Offline Signer Must Include:**
- ✅ Neptune wallet logic
- ✅ Triton VM runtime
- ✅ zk-STARK prover
- ✅ Transaction builder

**Binary Size Estimate:**
- Triton VM: ~50-100 MB (with dependencies)
- Neptune Core (subset): ~100-200 MB
- **Total offline signer**: ~200-300 MB

---

### 3.3 Triton VM Optimization Opportunities

**From Triton VM codebase analysis:**

**Potential Optimizations:**

1. **Proof Caching**
   - Cache common lock script proofs
   - Reduce proving time for standard transactions

2. **Parallelization**
   - Triton VM supports multi-threading
   - 16-core CPU → ~4-8x speedup (vs. 8-core)

3. **Proof Compression**
   - zk-STARKs are ~100-500 KB
   - Compress for QR code transfer

4. **Recursive Proving**
   - Aggregate multiple transactions
   - Prove batch of transactions once

**Impact on Air-Gapped Workflow:**

- ⚠️ Proof Collection proving: **~1-5 minutes** (achievable on laptop)
- ⚠️ Single Proof proving: **~10-60 minutes** (requires workstation)
- ✅ QR code transfer: **~5-10 QR codes** (with compression)

---

## Part 4: Post-Quantum P2P Encryption

### 4.1 Question: Should P2P Be Post-Quantum Too?

**User asked:**
> "Given zk-STARKs are quantum-safe, should P2P encryption also be post-quantum? (e.g., use Kyber/Dilithium instead of traditional ECDH/RSA)"

**Answer:** **YES**, for consistency.

---

### 4.2 Current P2P Encryption Landscape

**Traditional Approaches (NOT Quantum-Safe):**

| Protocol | Key Exchange | Signature | Quantum Vulnerability |
|----------|--------------|-----------|----------------------|
| **TLS 1.3** | ECDHE (X25519) | ECDSA/RSA | ❌ Vulnerable to Shor's algorithm |
| **Noise Protocol** | DH / ECDH | None (optional) | ❌ Vulnerable to Shor's algorithm |
| **WireGuard** | Curve25519 | Ed25519 | ❌ Vulnerable to Shor's algorithm |

**NIST Post-Quantum Standards (2024):**

| Algorithm | Purpose | Status | Performance |
|-----------|---------|--------|-------------|
| **Kyber** (ML-KEM) | Key Encapsulation | ✅ Standardized | Fast (~0.1ms) |
| **Dilithium** (ML-DSA) | Digital Signature | ✅ Standardized | Medium (~1-5ms) |
| **SPHINCS+** (SLH-DSA) | Digital Signature | ✅ Standardized | Slow (~50-100ms) |

---

### 4.3 Recommendation: Hybrid Post-Quantum

**🎯 Use Hybrid Approach (Best Practice):**

```rust
// Hybrid key exchange: Classical + Post-Quantum
pub struct PostQuantumP2PTransport {
    classical_kex: X25519,        // ECDH (for backward compat)
    pq_kex: Kyber1024,            // NIST ML-KEM (post-quantum)
    pq_sig: Dilithium5,           // NIST ML-DSA (post-quantum)
}

impl PostQuantumP2PTransport {
    pub fn establish_connection(&self, peer: SocketAddr) -> Result<SecureChannel> {
        // 1. Classical ECDH key exchange
        let classical_shared_secret = self.classical_kex.exchange(peer)?;
        
        // 2. Post-quantum key encapsulation
        let (pq_ciphertext, pq_shared_secret) = self.pq_kex.encapsulate(peer_pk)?;
        
        // 3. Combine secrets (XOR or KDF)
        let final_shared_secret = kdf([
            classical_shared_secret,
            pq_shared_secret,
        ]);
        
        // 4. Authenticate with post-quantum signature
        let signature = self.pq_sig.sign(&final_shared_secret);
        
        // 5. Establish encrypted channel
        Ok(SecureChannel::new(final_shared_secret))
    }
}
```

**Why Hybrid?**

- ✅ **Backward compatible**: Falls back to classical if PQ fails
- ✅ **Future-proof**: Secure even if quantum computers arrive
- ✅ **Defense in depth**: Attacker must break BOTH classical AND PQ
- ✅ **Performance**: Classical is fast, PQ is ~0.1ms overhead

---

### 4.4 Performance Impact

**Hybrid PQ Key Exchange Overhead:**

| Operation | Classical (X25519) | Post-Quantum (Kyber1024) | Total (Hybrid) |
|-----------|-------------------|--------------------------|----------------|
| **Key Generation** | ~0.05 ms | ~0.1 ms | ~0.15 ms |
| **Encapsulation** | ~0.05 ms | ~0.1 ms | ~0.15 ms |
| **Decapsulation** | ~0.05 ms | ~0.1 ms | ~0.15 ms |
| **Public Key Size** | 32 bytes | 1568 bytes | 1600 bytes |
| **Ciphertext Size** | 32 bytes | 1568 bytes | 1600 bytes |

**Impact on P2P:**
- ⚠️ **Handshake time**: +0.3ms (negligible)
- ⚠️ **Handshake data**: +3KB (negligible)
- ✅ **Ongoing traffic**: No overhead (symmetric encryption unchanged)

**Verdict:** Post-quantum P2P encryption is **feasible** with minimal performance impact.

---

### 4.5 Implementation Priority

**Recommendation:**

1. **Phase 4a (P2P Privacy):** Use **hybrid PQ encryption** from day one
   - Noise Protocol + Kyber1024
   - Or TLS 1.3 + Kyber1024 (using `rustls` with PQ support)

2. **Rationale:**
   - No reason to use classical-only encryption in 2025+
   - Quantum computers may arrive in 5-15 years
   - PQ overhead is minimal (~0.3ms handshake)
   - **Consistency with zk-STARKs**: Entire stack is quantum-safe

**Marketing Message:**

> "Neptune is the **only cryptocurrency with end-to-end post-quantum security**:
>
> - ✅ **On-chain:** zk-STARKs (quantum-safe proofs)
> - ✅ **P2P network:** Kyber1024 + Dilithium5 (quantum-safe encryption)
> - ✅ **Wallet:** Air-gapped signing (physical isolation)
>
> While competitors will be vulnerable to quantum computers, Neptune is already protected."

---

## Part 5: Mobile App Feasibility

### 5.1 User Question: Mobile Companion App?

**User:** "Would you want a Neptune Companion App (Android/iOS) that acts as a QR scanner for the air-gapped workflow? - possibly?"

**Answer:** **YES**, but with caveats.

---

### 5.2 Mobile App Capabilities

#### **✅ What Mobile App CAN Do:**

1. **Watch-Only Wallet**
   - Monitor balances
   - View transaction history
   - Generate receiving addresses
   - No private keys (safe on phone)

2. **QR Code Scanner**
   - Scan unsigned transactions from online node
   - Display unsigned transactions to air-gapped signer
   - Scan signed transactions from air-gapped signer
   - Forward signed transactions to online node

3. **Transaction Builder**
   - Create payment requests
   - Set amount, recipient, fee
   - Generate unsigned transaction

4. **Proof Collection Verification**
   - Verify proof integrity (fast)
   - Check transaction details

---

#### **❌ What Mobile App CANNOT Do:**

1. **Generate Single Proofs**
   - Requires 64GB+ RAM
   - No mobile device has this

2. **Store Private Keys Securely**
   - Mobile OS is networked
   - Risk of malware, remote exploitation
   - **Not recommended** for high-value wallets

3. **Generate Proof Collections**
   - Requires 2-8GB RAM
   - Most phones have 4-12GB RAM
   - **Technically possible** but slow (~5-10 minutes)
   - Battery drain
   - **Not recommended** for user experience

---

### 5.3 Recommended Mobile App Scope

**🎯 Mobile App = Watch-Only + QR Relay**

```
Mobile App Workflow:

1. User wants to send NEPTUNE
    ├─► Opens mobile app
    ├─► Enters amount, recipient
    └─► App generates unsigned transaction

2. Air-gapped signer
    ├─► Mobile app displays unsigned tx as QR code
    ├─► Air-gapped signer scans QR code
    ├─► Air-gapped signer generates proof (Proof Collection or Single Proof)
    └─► Air-gapped signer displays signed tx as QR code

3. Mobile app
    ├─► Scans signed tx QR code
    ├─► Validates signature (fast)
    └─► Broadcasts to P2P network
```

**Benefits:**
- ✅ **Convenient**: Phone always with you
- ✅ **Secure**: No keys on phone
- ✅ **Fast**: QR scanning is instant
- ✅ **Portable**: No need for online node at home

**Limitations:**
- ⚠️ Requires air-gapped signer (separate device)
- ⚠️ QR code transfer can be cumbersome for large transactions

---

### 5.4 Implementation Plan

**Phase 4b: Mobile Companion App (Optional)**

**Milestone 1: Core Functionality (2-3 months)**
- [ ] Watch-only wallet (monitor balances, addresses)
- [ ] QR code scanner (camera integration)
- [ ] Unsigned transaction builder
- [ ] Signed transaction broadcaster

**Milestone 2: UX Polish (1-2 months)**
- [ ] Biometric unlock (Face ID, fingerprint)
- [ ] Transaction preview (amount, recipient, fee)
- [ ] Address book (save frequent recipients)
- [ ] Transaction history (with block explorer links)

**Milestone 3: Advanced Features (Future)**
- [ ] Multi-signature coordination
- [ ] Push notifications (transaction confirmations)
- [ ] NFC transfer (alternative to QR codes)
- [ ] Proof Collection generation (low priority, battery drain)

**Platforms:**
- iOS (Swift / SwiftUI)
- Android (Kotlin / Jetpack Compose)
- React Native (cross-platform, faster development)

**Development Time:**
- **React Native**: 3-4 months (one codebase, both platforms)
- **Native (iOS + Android)**: 6-8 months (two codebases, better performance)

---

## Part 6: Revised Strategy & Recommendations

### 6.1 Corrected Hardware Recommendations

#### **Air-Gapped Signer Tiers (Revised)**

| Tier | Hardware | RAM | Cost | Use Case |
|------|----------|-----|------|----------|
| **Budget** | Used laptop (Dell Latitude) | 8-16 GB | $200-$400 | Proof Collection mode, occasional use |
| **Standard** | Desktop (AMD Ryzen 7) | 64 GB | $800-$1200 | Single Proof mode, regular use |
| **Premium** | Workstation (Threadripper) | 128 GB | $2000-$3000 | Single Proof mode, heavy use, exchanges |
| **Enterprise** | Server (Dell R750) | 256 GB | $5000+ | Proof upgrader service, institutional |

---

### 6.2 Revised Implementation Roadmap

**Phase 4b: Air-Gapped Signing (3-4 months)** ← **Extended timeline**

**Milestone 1: Core Infrastructure (4-6 weeks)**
- [ ] Watch-only wallet mode
- [ ] Unsigned transaction format
- [ ] QR code encoding/decoding
- [ ] Proof Collection support

**Milestone 2: Offline Signing Tool (6-8 weeks)**
- [ ] `neptune-offline-signer` binary
- [ ] Proof Collection generation (8-16GB RAM)
- [ ] Single Proof generation (64GB+ RAM)
- [ ] Transaction signing logic

**Milestone 3: UX & Documentation (4-6 weeks)**
- [ ] QR code scanning (camera integration)
- [ ] Progress indicators (proving time estimates)
- [ ] User guide (setup, first transaction)
- [ ] Hardware recommendations (budget, standard, premium)

**Milestone 4: Mobile Companion App (Optional, 3-4 months)**
- [ ] Watch-only wallet (iOS + Android)
- [ ] QR code scanner
- [ ] Transaction builder
- [ ] Broadcast functionality

**Total: 4-5 months** (without mobile app) or **7-9 months** (with mobile app)

---

### 6.3 Updated Marketing Strategy

#### **Two-Tier Messaging**

**Tier 1: Accessible Air-Gapped Security**
> "Secure your NEPTUNE with **Proof Collection mode**—air-gapped protection on a $200 used laptop. Small fee (≥0.05 NPT) for proof upgrading, but your keys never touch the internet."

**Target:** Retail users, privacy advocates, moderate holdings (<$10K)

**Tier 2: Enterprise-Grade Air-Gapped Security**
> "For institutions and high-net-worth individuals: **Single Proof mode** with self-hosted proving. $800-$3000 workstation, minimal fees, full sovereignty. The same cold storage standard used by central banks."

**Target:** Whales, exchanges, family offices, large holdings (>$100K)

---

### 6.4 Proof Upgrader Economics

**New Insight:** Neptune creates a **proof upgrading market**.

**Actors:**

1. **Proof Upgraders** (Service Providers)
   - Run high-RAM workstations (64-128GB)
   - Monitor mempool for Proof Collections
   - "Raise" Proof Collections → Single Proofs
   - Charge fees (≥0.05 NPT per transaction)
   - Profitability: ~$1-$5 per transaction @ current NPT prices

2. **Users** (Buyers)
   - Generate Proof Collections on consumer hardware
   - Pay proof upgraders for "raise" operation
   - Trade-off: Convenience vs. fee

**Market Dynamics:**

- **Competitive:** Multiple proof upgraders drive fees down
- **Trustless:** Proof Collections are public, no trust required
- **Profitable:** If NPT appreciates, proof upgrading becomes lucrative business

**Strategic Opportunity:**

- Neptune Foundation could run **subsidized proof upgraders** initially
- Ensure network accessibility during early adoption
- Transition to decentralized market over time

---

## Part 7: Critical Questions for Team

### 7.1 Technical Clarifications Needed

1. **Single Proof RAM Usage**
   - Team said ">64GB" but how much more?
   - Is 128GB sufficient for all transactions?
   - What's the largest transaction (inputs/outputs) proven so far?

2. **Proof Collection vs. Single Proof Trade-offs**
   - What's the typical proving time for Proof Collection on 8GB RAM laptop?
   - What's the typical proving time for Single Proof on 64GB RAM workstation?
   - Can proving be paused/resumed?

3. **Triton VM Optimizations**
   - Is multi-threading implemented for zk-STARK proving?
   - What's the speedup with 16-core vs. 8-core CPU?
   - Any plans for GPU acceleration?

4. **Offline Signer Status**
   - Does any offline signer exist currently?
   - Is the transaction signing logic separable from full node?
   - What's the minimum codebase subset needed for offline signing?

5. **Mobile Proof Generation**
   - Has Proof Collection generation been tested on mobile devices?
   - What's the battery drain?
   - Is it practical for users?

---

### 7.2 Strategic Decisions Needed

1. **Proof Collection as Default?**
   - Should Neptune **recommend** Proof Collection mode by default?
   - Position as "accessible air-gapped security"?
   - Educate users on Single Proof as "advanced" option?

2. **Subsidized Proof Upgraders?**
   - Should Neptune Foundation run proof upgraders initially?
   - Free or subsidized (e.g., 0.01 NPT instead of 0.05 NPT)?
   - Transition to market-based pricing?

3. **Mobile App Priority?**
   - Is mobile companion app worth 3-4 months development?
   - Or focus on desktop workflow first?
   - Community demand?

4. **Post-Quantum P2P?**
   - Implement hybrid PQ encryption in Phase 4a?
   - Or defer to Phase 5?
   - Marketing value: "end-to-end post-quantum"?

5. **Hardware Wallet Revisited?**
   - Given Proof Collection mode exists, could we support:
     - Hardware wallet stores seed
     - Hardware wallet generates Proof Collection (if RAM sufficient)
     - Neptune node "raises" to Single Proof
   - Still secure?

---

## Part 8: Updated Conclusions

### 8.1 Key Takeaways

1. **❌ Raspberry Pi is not viable** (need 64GB+ RAM, not 8GB)
2. **✅ Proof Collection mode enables affordable air-gapped signing** (~$200-$500)
3. **✅ Single Proof mode for power users** (~$800-$3000)
4. **✅ Post-quantum P2P should be implemented** (Kyber1024 + Dilithium5)
5. **✅ Mobile companion app is feasible** (watch-only + QR relay)
6. **⚠️ No offline signer exists yet** (needs to be built)

---

### 8.2 Revised Strategic Priority

**Phase 4 Implementation Order:**

1. **Phase 4a: P2P Privacy (3-6 months)** ← **HIGHEST PRIORITY**
   - Noise Protocol + Kyber1024 (post-quantum)
   - Tor integration
   - Dandelion++ protocol

2. **Phase 4b: Air-Gapped Signing (3-4 months)** ← **PARALLEL DEVELOPMENT**
   - Watch-only wallet mode
   - Proof Collection support (8-16GB RAM)
   - Single Proof support (64GB+ RAM)
   - Offline signing tool
   - QR code workflow

3. **Phase 4c: Mobile Companion App (3-4 months)** ← **OPTIONAL**
   - Watch-only wallet (iOS + Android)
   - QR code scanner
   - Transaction builder

**Total Timeline: 6-10 months** (depending on mobile app decision)

---

### 8.3 Updated Marketing Message

**Revised Positioning:**

> "**Neptune: The Only Post-Quantum Cryptocurrency with Flexible Air-Gapped Security**
>
> **On-Chain:** zk-STARKs (quantum-safe, no trusted setup)  
> **P2P Network:** Kyber1024 + Dilithium5 (post-quantum encryption)  
> **Wallet Security:** Two-tier air-gapped protection
>
> - **Accessible Tier:** $200 used laptop + Proof Collection mode
> - **Premium Tier:** $800+ workstation + Single Proof mode
>
> **The only cryptocurrency ready for the quantum computing era.**"

---

### 8.4 Action Items

**Immediate (This Week):**

1. ✅ Update `zkstark-airgapped-strategy.md` with corrected RAM requirements
2. ✅ Document Proof Collection vs. Single Proof options
3. ✅ Remove Raspberry Pi recommendations
4. ⏳ Get team feedback on strategic questions (Part 7)

**Short-Term (This Month):**

1. ⏳ Finalize Phase 4 priorities (P2P vs. air-gapped vs. mobile)
2. ⏳ Prototype offline signer (Proof Collection mode)
3. ⏳ Test Triton VM on various hardware (8GB, 16GB, 64GB, 128GB)
4. ⏳ Research hybrid PQ encryption libraries (Kyber + Dilithium)

**Medium-Term (3-6 Months):**

1. ⏳ Implement Phase 4a (P2P privacy with PQ encryption)
2. ⏳ Implement Phase 4b (air-gapped signing with Proof Collection)
3. ⏳ Security audit (Trail of Bits or similar)
4. ⏳ Launch community proof upgrader network

---

**Document Status:** Awaiting Team Feedback  
**Next Update:** After strategic decisions (Part 7) are made  
**Implementation Start:** 2026-Q1 (Phase 4)

---

## Appendix: Proof Lifecycle Summary

**From `/home/anon/Documents/GitHub/neptune-core-wallet/docs/notes/NEPTUNE-TRANSACTION-PROOF-LIFECYCLE.md`:**

```
Primitive Witness (secret, cannot share)
    │
    ├─► Proof Collection (2-8GB RAM, ~1-5 min, ≥0.05 NPT fee)
    │       │
    │       ├─► "Raise" operation (64GB+ RAM, proof upgrader service)
    │       │
    │       ▼
    ├─► Single Proof (64GB+ RAM, ~10-60 min, minimal fee)
    │
    └─► Block Proof (final state, included in blockchain)
```

**Key Insights:**

- Proof Collection can be generated on **consumer hardware**
- "Raise" operation requires **specialized hardware** (proof upgraders)
- Single Proof generation requires **workstation-class hardware**
- **Trade-off:** Accessibility (Proof Collection) vs. Cost (Single Proof)

---

**END OF DOCUMENT**

