# PassCrypt

**Hyper‑secure Python-based program that heavily encrypts and obfuscates strings. Supports single or multi-password mode with 5 cryptographic layers for maximum security.**

PassCrypt provides five layers of encryption for enhanced security:

1. Bit-level transformation with password-derived keystream  
2. Block-based permutation  
3. S-box substitution  
4. Multi-stream XOR cipher  
5. Full cryptographic layer with decoy bytes and PKCS7 padding

It supports multi-password mode, HMAC-SHA256 integrity verification, Base85 display or binary storage, and cross-platform CLI usage.
Use it for any passwords stored locally, journals, etc. 

---

## Installation and Usage

Clone the repository and navigate into it:

```bash
git clone https://github.com/Banois/passcrypt.git
cd passcrypt
python passcrypt.py
```

## Tools

compare.bat will comapre two different files of your choosing and display the difference in characters.
counter.bat will simply display file difference in numbers. 
displayer.py is essential if you need to write down files using the simple encryption. Basic localhost flask application. 

## Updates

* Version 5.3 has been released. 
* File selection comes first compared to the previous password > file selection step so the user can retry if they mess up the password.
* Added an option to copy password output to clipboard.
* Added an option to hide the typed password from being displayed.
* Added increased clearing security when the script ends.
* Users can now quick convert an old file with a warning that the version header might be outdated if they convert.
* With the addition of converting files (and new releases in the future) I will be adding old versions in a folder.
* Added a "runpasscrypt.vbs" in case the user wants to quick run the file due to potential compatability & convenience for startup shortcuts.
* Removed strengthcheck.py from tools as it is obselete and detection is bad.
* Added readme.md clarification on tool uses. 
