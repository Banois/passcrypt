# PassCrypt

**Hyper‑secure Python-based program that heavily encrypts and obfuscates strings. Supports single or multi-password mode with 5 cryptographic layers for maximum security.**

PassCrypt provides five layers of encryption for enhanced security:

1. Bit-level transformation with password-derived keystream  
2. Block-based permutation  
3. S-box substitution  
4. Multi-stream XOR cipher  
5. Full cryptographic layer with decoy bytes and PKCS7 padding

It supports multi-password mode, HMAC-SHA256 integrity verification, Base85 display or binary storage, and cross-platform CLI usage. You can also set a character limit for encrypted output to add additional obfuscation.

---

## Installation and Usage

Clone the repository and navigate into it:

```bash
git clone https://github.com/yourusername/passcrypt.git
cd passcrypt
python passcrypt.py
