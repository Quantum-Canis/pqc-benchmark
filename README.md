**Post-Quantum Cryptographic Benchmarking for Satellite Systems**

This repository contains all benchmarking scripts, configuration files, and analysis tools used in the accompanying master's thesis:  
**“Benchmarking Post-Quantum Cryptographic Algorithms for Satellite Systems”**

The goal of this project is to assess the feasibility of NIST-standardized post-quantum cryptographic (PQC) algorithms under system constraints representative of satellite communication environments. It evaluates timing performance, consistency, key/ciphertext/signature sizes, and variance across multiple PQC and classical algorithms.

---

## 📌 Algorithms Evaluated

- **ML-KEM** (based on CRYSTALS-Kyber)
- **ML-DSA** (based on CRYSTALS-Dilithium)
- **SPHINCS+** (stateless hash-based signatures)
- **HQC** (Hamming Quasi-Cyclic KEM)
- **RSA-2048 / RSA-OAEP / ECDSA / Ed25519** (classical baselines)

---

## 🔬 Features

- Consistent benchmarking across 100 iterations per operation
- CV and max/median analysis for runtime stability
- Output size tracking (key, signature)
- Easy-to-read logs and configurable output directories

---

## 🛠️ Requirements

- Python 3.8+
- [Open Quantum Safe (liboqs)](https://openquantumsafe.org/)
- `os`, `json`, `cryptography`, `csv`, `pathlib`, `statistics`, `time`, `mysql.connector`, `datetime`, `dotenv`

---
