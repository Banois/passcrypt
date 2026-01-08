import base64
import hashlib
import secrets
import hmac
import os
from typing import Tuple, List, Optional

# =============================================================================
# VERSION & CONSTANTS
# =============================================================================

VERSION = b'PC51'  # PassCrypt v5.1 format identifier

# =============================================================================
# INPUT HELPERS
# =============================================================================

class UserExit(Exception):
    """Raised when user types 'exit' to quit"""
    pass

def get_input(prompt: str, allow_empty: bool = False) -> str:
    """Get input with exit command support"""
    while True:
        value = input(prompt).strip()
        if value.lower() == 'exit':
            raise UserExit()
        if value or allow_empty:
            return value
        print("Input cannot be empty. Type 'exit' to quit.")

def get_choice(prompt: str, valid_choices: list) -> str:
    """Get a validated choice with retry"""
    while True:
        value = get_input(prompt)
        if value in valid_choices:
            return value
        print(f"Invalid choice. Please enter one of: {', '.join(valid_choices)}")

def get_yes_no(prompt: str) -> bool:
    """Get yes/no input with retry"""
    while True:
        value = get_input(prompt).lower()
        if value in ['y', 'yes']:
            return True
        if value in ['n', 'no']:
            return False
        print("Please enter 'y' or 'n'.")

def get_int(prompt: str, min_val: int = None) -> int:
    """Get integer input with validation"""
    while True:
        value = get_input(prompt)
        try:
            num = int(value)
            if min_val is not None and num < min_val:
                print(f"Value must be at least {min_val}.")
                continue
            return num
        except ValueError:
            print("Please enter a valid number.")

# =============================================================================
# KEY DERIVATION & AUTHENTICATION HELPERS
# =============================================================================

def _derive_key(password: str, salt: bytes, iterations: int = 100000) -> bytes:
    """Derive a cryptographic key from password using PBKDF2"""
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)

def _derive_layer_keys(master: str, salt: bytes) -> List[str]:
    """Derive all layer keys from a single master password using HKDF-like expansion"""
    # Single PBKDF2 call with high iterations
    master_key = _derive_key(master, salt, iterations=100000)
    
    # Derive layer keys using HMAC with context labels
    layer_keys = []
    for i in range(1, 6):
        layer_key = hmac.new(master_key, f'layer{i}'.encode(), hashlib.sha256).hexdigest()
        layer_keys.append(layer_key)
    
    return layer_keys

def _hmac_sign(key: bytes, data: bytes) -> bytes:
    """Create HMAC-SHA256 signature for integrity verification"""
    return hmac.new(key, data, hashlib.sha256).digest()

def _xor_bytes(data: bytes, key: bytes) -> bytes:
    """XOR data with repeating key"""
    key_len = len(key)
    return bytes(d ^ key[i % key_len] for i, d in enumerate(data))

def _generate_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """Generate a cryptographic keystream using SHA256 in counter mode"""
    keystream = b''
    counter = 0
    while len(keystream) < length:
        keystream += hashlib.sha256(key + nonce + counter.to_bytes(4, 'big')).digest()
        counter += 1
    return keystream[:length]

def _create_permutation(key: bytes, nonce: bytes, length: int) -> list:
    """Create a cryptographic permutation using hash-based Fisher-Yates"""
    perm_seed = hashlib.sha256(key + nonce).digest()
    
    perm = list(range(length))
    for i in range(length - 1, 0, -1):
        # Derive index from hash chain (deterministic, portable)
        idx_bytes = hashlib.sha256(perm_seed + i.to_bytes(4, 'big')).digest()
        j = int.from_bytes(idx_bytes[:4], 'big') % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    return perm

def _apply_permutation(data: bytes, perm: list) -> bytes:
    """Apply a permutation to data"""
    return bytes(data[perm[i]] for i in range(len(data)))

def _reverse_permutation(data: bytes, perm: list) -> bytes:
    """Reverse a permutation on data"""
    n = len(data)
    inv_perm = [0] * n
    for i in range(n):
        inv_perm[perm[i]] = i
    return bytes(data[inv_perm[i]] for i in range(n))

# =============================================================================
# LAYER 1: Bit-level transformation with password-derived key
# =============================================================================

def layer1_encrypt(data: bytes, password: str) -> bytes:
    """Layer 1: Bit manipulation with password-derived keystream"""
    salt = secrets.token_bytes(8)
    key = _derive_key(password, salt, iterations=10000)
    nonce = secrets.token_bytes(8)
    
    keystream = _generate_keystream(key, nonce, len(data))
    xored = _xor_bytes(data, keystream)
    
    rotation_key = hashlib.sha256(key + b'rotate').digest()
    rotated = bytearray()
    for i, byte in enumerate(xored):
        rot = rotation_key[i % 32] % 8
        rotated.append(((byte << rot) | (byte >> (8 - rot))) & 0xFF)
    
    hmac_sig = _hmac_sign(key, bytes(rotated))[:16]
    return salt + nonce + hmac_sig + bytes(rotated)

def layer1_decrypt(data: bytes, password: str) -> bytes:
    """Reverse layer 1"""
    if len(data) < 32:
        raise ValueError("Decryption failed")
    
    salt, nonce, stored_hmac, encrypted = data[:8], data[8:16], data[16:32], data[32:]
    key = _derive_key(password, salt, iterations=10000)
    
    if not hmac.compare_digest(_hmac_sign(key, encrypted)[:16], stored_hmac):
        raise ValueError("Decryption failed")
    
    rotation_key = hashlib.sha256(key + b'rotate').digest()
    unrotated = bytearray()
    for i, byte in enumerate(encrypted):
        rot = rotation_key[i % 32] % 8
        unrotated.append(((byte >> rot) | (byte << (8 - rot))) & 0xFF)
    
    keystream = _generate_keystream(key, nonce, len(unrotated))
    return _xor_bytes(bytes(unrotated), keystream)

# =============================================================================
# LAYER 2: Block cipher simulation with permutation
# =============================================================================

def layer2_encrypt(data: bytes, password: str) -> bytes:
    """Layer 2: Block-based permutation encryption"""
    salt = secrets.token_bytes(8)
    key = _derive_key(password, salt, iterations=15000)
    nonce = secrets.token_bytes(8)
    
    n = len(data)
    perm = _create_permutation(key, nonce, n)
    permuted = _apply_permutation(data, perm)
    
    keystream = _generate_keystream(hashlib.sha256(key + b'block').digest(), nonce, n)
    encrypted = _xor_bytes(permuted, keystream)
    
    hmac_sig = _hmac_sign(key, encrypted)[:16]
    return salt + nonce + hmac_sig + encrypted

def layer2_decrypt(data: bytes, password: str) -> bytes:
    """Reverse layer 2"""
    if len(data) < 32:
        raise ValueError("Decryption failed")
    
    salt, nonce, stored_hmac, encrypted = data[:8], data[8:16], data[16:32], data[32:]
    key = _derive_key(password, salt, iterations=15000)
    
    if not hmac.compare_digest(_hmac_sign(key, encrypted)[:16], stored_hmac):
        raise ValueError("Decryption failed")
    
    n = len(encrypted)
    keystream = _generate_keystream(hashlib.sha256(key + b'block').digest(), nonce, n)
    permuted = _xor_bytes(encrypted, keystream)
    
    perm = _create_permutation(key, nonce, n)
    return _reverse_permutation(permuted, perm)

# =============================================================================
# LAYER 3: Substitution cipher with password-derived S-box
# =============================================================================

def _generate_sbox(key: bytes) -> Tuple[bytes, bytes]:
    """Generate S-box using cryptographic hash chain (portable across Python versions)"""
    sbox_seed = hashlib.sha256(key + b'sbox').digest()
    
    sbox = list(range(256))
    for i in range(255, 0, -1):
        idx_bytes = hashlib.sha256(sbox_seed + i.to_bytes(2, 'big')).digest()
        j = int.from_bytes(idx_bytes[:4], 'big') % (i + 1)
        sbox[i], sbox[j] = sbox[j], sbox[i]
    
    inv_sbox = [0] * 256
    for i, v in enumerate(sbox):
        inv_sbox[v] = i
    
    return bytes(sbox), bytes(inv_sbox)

def layer3_encrypt(data: bytes, password: str) -> bytes:
    """Layer 3: S-box substitution"""
    salt = secrets.token_bytes(8)
    key = _derive_key(password, salt, iterations=20000)
    sbox, _ = _generate_sbox(key)
    
    result = bytearray()
    for i, byte in enumerate(data):
        pos_key = hashlib.sha256(key + i.to_bytes(4, 'big')).digest()[0]
        result.append(sbox[(byte + pos_key) % 256])
    
    hmac_sig = _hmac_sign(key, bytes(result))[:16]
    return salt + hmac_sig + bytes(result)

def layer3_decrypt(data: bytes, password: str) -> bytes:
    """Reverse layer 3"""
    if len(data) < 24:
        raise ValueError("Decryption failed")
    
    salt, stored_hmac, encrypted = data[:8], data[8:24], data[24:]
    key = _derive_key(password, salt, iterations=20000)
    
    if not hmac.compare_digest(_hmac_sign(key, encrypted)[:16], stored_hmac):
        raise ValueError("Decryption failed")
    
    _, inv_sbox = _generate_sbox(key)
    
    result = bytearray()
    for i, byte in enumerate(encrypted):
        inv_sub = inv_sbox[byte]
        pos_key = hashlib.sha256(key + i.to_bytes(4, 'big')).digest()[0]
        result.append((inv_sub - pos_key) % 256)
    
    return bytes(result)

# =============================================================================
# LAYER 4: Stream cipher with multiple keystream mixing
# =============================================================================

def layer4_encrypt(data: bytes, password: str) -> bytes:
    """Layer 4: Multi-stream XOR cipher"""
    salt = secrets.token_bytes(8)
    key = _derive_key(password, salt, iterations=25000)
    nonce = secrets.token_bytes(8)
    
    n = len(data)
    key1 = hashlib.sha256(key + b'stream1').digest()
    key2 = hashlib.sha256(key + b'stream2').digest()
    key3 = hashlib.sha256(key + b'stream3').digest()
    
    ks1 = _generate_keystream(key1, nonce, n)
    ks2 = _generate_keystream(key2, nonce[::-1], n)
    ks3 = _generate_keystream(key3, hashlib.sha256(nonce).digest()[:8], n)
    
    encrypted = bytes(d ^ k1 ^ k2 ^ k3 for d, k1, k2, k3 in zip(data, ks1, ks2, ks3))
    
    hmac_sig = _hmac_sign(key, encrypted)[:16]
    return salt + nonce + hmac_sig + encrypted

def layer4_decrypt(data: bytes, password: str) -> bytes:
    """Reverse layer 4"""
    if len(data) < 32:
        raise ValueError("Decryption failed")
    
    salt, nonce, stored_hmac, encrypted = data[:8], data[8:16], data[16:32], data[32:]
    key = _derive_key(password, salt, iterations=25000)
    
    if not hmac.compare_digest(_hmac_sign(key, encrypted)[:16], stored_hmac):
        raise ValueError("Decryption failed")
    
    n = len(encrypted)
    key1 = hashlib.sha256(key + b'stream1').digest()
    key2 = hashlib.sha256(key + b'stream2').digest()
    key3 = hashlib.sha256(key + b'stream3').digest()
    
    ks1 = _generate_keystream(key1, nonce, n)
    ks2 = _generate_keystream(key2, nonce[::-1], n)
    ks3 = _generate_keystream(key3, hashlib.sha256(nonce).digest()[:8], n)
    
    return bytes(e ^ k1 ^ k2 ^ k3 for e, k1, k2, k3 in zip(encrypted, ks1, ks2, ks3))

# =============================================================================
# LAYER 5: Full cryptographic layer with simplified marker system
# Uses single 1-byte marker per real byte (no rotation) for reliable parsing
# =============================================================================

def layer5_encrypt(data: bytes, password: str, max_length: int = None) -> bytes:
    """
    Layer 5: Full cryptographic encryption with:
    - Random salt + nonce
    - PBKDF2 key derivation (50k iterations)
    - HMAC authentication (16 bytes)
    - Single marker byte per data byte (reliable parsing)
    - Decoy injection with cryptographic randomness
    - PKCS7 padding to hide exact length
    """
    if not data:
        return data
    
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(16)
    
    enc_key = _derive_key(password, salt, iterations=50000)
    transform_key = hashlib.sha256(enc_key + b'transform').digest()
    marker_key = hashlib.sha256(enc_key + b'markers').digest()
    hmac_key = hashlib.sha256(enc_key + b'hmac').digest()
    
    # Generate single marker byte (derived from key)
    marker = marker_key[0]
    
    # PKCS7 padding
    padding_len = 16 - (len(data) % 16)
    padded_data = data + bytes([padding_len] * padding_len)
    n = len(padded_data)
    
    # Apply permutation + XOR
    perm = _create_permutation(transform_key, nonce, n)
    permuted = _apply_permutation(padded_data, perm)
    keystream = _generate_keystream(transform_key, nonce, n)
    encrypted = _xor_bytes(permuted, keystream)
    
    # Calculate minimum output size: header(48) + (marker + byte) * n = 48 + 2n
    min_size = 48 + (n * 2)
    
    if max_length is not None and max_length < min_size:
        raise ValueError(f"max_length ({max_length}) too small. Minimum: {min_size}")
    
    # Build output: marker + byte + decoys for each byte
    result_bytes = bytearray()
    
    for i, byte_val in enumerate(encrypted):
        # XOR data byte with marker to avoid accidental marker appearance
        encoded_byte = byte_val ^ marker
        result_bytes.append(marker)
        result_bytes.append(encoded_byte)
        
        # Add decoys between real bytes (not after last)
        if i < n - 1:
            if max_length is not None:
                remaining_bytes = n - i - 1
                remaining_needed = remaining_bytes * 2
                space_left = max_length - 48 - len(result_bytes) - remaining_needed
                max_decoys = max(0, min(8, space_left))
            else:
                max_decoys = 8
            
            # Ensure at least some decoys for obfuscation
            min_decoys = 1 if max_decoys > 0 else 0
            num_decoys = min_decoys + secrets.randbelow(max(1, max_decoys - min_decoys + 1)) if max_decoys > 0 else 0
            
            for _ in range(num_decoys):
                # Generate decoy that isn't the marker byte
                decoy = secrets.token_bytes(1)[0]
                while decoy == marker:
                    decoy = secrets.token_bytes(1)[0]
                result_bytes.append(decoy)
    
    hmac_sig = _hmac_sign(hmac_key, bytes(result_bytes))[:16]
    
    # Header: salt(16) + nonce(16) + hmac(16) = 48 bytes
    return salt + nonce + hmac_sig + bytes(result_bytes)

def layer5_decrypt(data: bytes, password: str) -> bytes:
    """Reverse layer 5 encryption"""
    if not data:
        return data
    
    if len(data) < 48:
        raise ValueError("Decryption failed")
    
    salt, nonce, stored_hmac, encrypted_data = data[:16], data[16:32], data[32:48], data[48:]
    
    enc_key = _derive_key(password, salt, iterations=50000)
    transform_key = hashlib.sha256(enc_key + b'transform').digest()
    marker_key = hashlib.sha256(enc_key + b'markers').digest()
    hmac_key = hashlib.sha256(enc_key + b'hmac').digest()
    
    if not hmac.compare_digest(_hmac_sign(hmac_key, encrypted_data)[:16], stored_hmac):
        raise ValueError("Decryption failed")
    
    marker = marker_key[0]
    
    # Extract real bytes: find marker, next byte is XORed data
    real_bytes = bytearray()
    i = 0
    while i < len(encrypted_data):
        if encrypted_data[i] == marker:
            if i + 1 < len(encrypted_data):
                # Decode by XORing with marker
                real_bytes.append(encrypted_data[i + 1] ^ marker)
                i += 2
            else:
                i += 1
        else:
            # Skip decoy
            i += 1
    
    if not real_bytes:
        raise ValueError("Decryption failed")
    
    n = len(real_bytes)
    
    # Reverse XOR + permutation
    keystream = _generate_keystream(transform_key, nonce, n)
    permuted = _xor_bytes(bytes(real_bytes), keystream)
    perm = _create_permutation(transform_key, nonce, n)
    unpadded = _reverse_permutation(permuted, perm)
    
    # Remove PKCS7 padding
    padding_len = unpadded[-1]
    if padding_len > 16 or padding_len == 0:
        raise ValueError("Decryption failed")
    if unpadded[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Decryption failed")
    
    return unpadded[:-padding_len]

# =============================================================================
# ENCODING HELPERS
# =============================================================================

def _simple_encode(data: bytes) -> str:
    """Encode bytes to printable ASCII using base85"""
    return base64.b85encode(data).decode('ascii')

def _simple_decode(text: str) -> bytes:
    """Decode base85 text to bytes"""
    try:
        return base64.b85decode(text.encode('ascii'))
    except Exception:
        raise ValueError("Invalid encoded text")

# =============================================================================
# MAIN ENCRYPTION/DECRYPTION PIPELINES
# =============================================================================

def encrypt_text(text: str, passwords: List[str], max_length: int = None) -> bytes:
    """Apply all 5 layers of encryption with version header."""
    # Generate salt for key derivation (only used in single-master mode)
    key_salt = secrets.token_bytes(16)
    
    if len(passwords) == 1:
        # Single master password - derive keys properly
        layer_passwords = _derive_layer_keys(passwords[0], key_salt)
    elif len(passwords) == 5:
        layer_passwords = passwords
        key_salt = b'\x00' * 16  # Not used in multi-password mode
    else:
        raise ValueError("Must provide exactly 1 (master) or 5 (multi) passwords")
    
    data = text.encode('utf-8')
    
    # Apply layers
    data = layer1_encrypt(data, layer_passwords[0])
    data = layer2_encrypt(data, layer_passwords[1])
    data = layer3_encrypt(data, layer_passwords[2])
    data = layer4_encrypt(data, layer_passwords[3])
    data = layer5_encrypt(data, layer_passwords[4], max_length)
    
    # Prepend version + key_salt
    return VERSION + key_salt + data

def decrypt_text(data: bytes, passwords: List[str]) -> str:
    """Reverse all 5 layers of encryption."""
    # Check version
    if len(data) < 20:
        raise ValueError("Decryption failed")
    
    version = data[:4]
    if version != VERSION:
        raise ValueError("Decryption failed - incompatible format version")
    
    key_salt = data[4:20]
    encrypted = data[20:]
    
    if len(passwords) == 1:
        layer_passwords = _derive_layer_keys(passwords[0], key_salt)
    elif len(passwords) == 5:
        layer_passwords = passwords
    else:
        raise ValueError("Must provide exactly 1 (master) or 5 (multi) passwords")
    
    # Reverse layers
    data = layer5_decrypt(encrypted, layer_passwords[4])
    data = layer4_decrypt(data, layer_passwords[3])
    data = layer3_decrypt(data, layer_passwords[2])
    data = layer2_decrypt(data, layer_passwords[1])
    data = layer1_decrypt(data, layer_passwords[0])
    
    return data.decode('utf-8')

# =============================================================================
# MAIN CLI
# =============================================================================

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    
    print("PassCrypt v5.1 - 5-Layer Encryption Tool")
    print("=" * 42)
    print("Type 'exit' at any prompt to quit.\n")
    
    try:
        choice = get_choice("Enter 1 to encrypt or 2 to decrypt: ", ['1', '2'])
        mode_choice = get_choice("Enter 1 for simple (Base85) or 2 for advanced (binary file): ", ['1', '2'])
        mode = 'simple' if mode_choice == '1' else 'advanced'
        
        pw_mode = get_choice("Enter 1 for single master password or 2 for 5 separate passwords: ", ['1', '2'])
        multi_password = (pw_mode == '2')
        
        # Collect passwords
        if multi_password:
            print("\nEnter 5 passwords (one for each layer):")
            passwords = []
            for i in range(1, 6):
                pw = get_input(f"  Layer {i} password: ")
                passwords.append(pw)
        else:
            passwords = [get_input("\nEnter master password: ")]
        
        if choice == '2':
            # DECRYPTION
            input_choice = get_choice("\nEnter 1 to input from file or 2 to input text directly: ", ['1', '2'])
            
            if input_choice == '1':
                file_path = None
                
                if os.name == 'nt':
                    try:
                        import tkinter as tk
                        from tkinter import filedialog
                        
                        print("\nOpening file explorer...")
                        root = tk.Tk()
                        root.withdraw()
                        root.attributes('-topmost', True)
                        
                        file_path = filedialog.askopenfilename(
                            title="Select encrypted file",
                            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
                        )
                        root.destroy()
                        
                        if not file_path:
                            print("No file selected.")
                            file_path = None
                    except Exception:
                        file_path = None
                
                if not file_path:
                    file_path = get_input("Enter file path: ")
                
                try:
                    if mode == 'advanced':
                        with open(file_path, 'rb') as f:
                            raw_data = f.read()
                    else:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            raw_data = f.read().strip()
                    print(f"Loaded from: {file_path}")
                except FileNotFoundError:
                    print(f"File not found: {file_path}")
                    return
                except Exception as e:
                    print(f"Error reading file: {e}")
                    return
            else:
                raw_data = get_input("Enter encrypted text: ")
            
            try:
                if mode == 'simple':
                    encrypted_bytes = _simple_decode(raw_data)
                else:
                    encrypted_bytes = raw_data if isinstance(raw_data, bytes) else raw_data.encode('latin-1')
                
                decrypted = decrypt_text(encrypted_bytes, passwords)
                
                if get_yes_no("\nShow decrypted text? (y/n): "):
                    print(f"\nDecrypted text:\n{decrypted}")
                
                if get_yes_no("\nSave to file? (y/n): "):
                    filename = get_input("Enter filename: ")
                    script_dir = os.path.dirname(os.path.abspath(__file__))
                    filepath = os.path.join(script_dir, filename)
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(decrypted)
                    print(f"Saved to: {filepath}")
                
            except ValueError as e:
                print(f"\nDecryption failed. Check password and mode.")
            except Exception as e:
                print(f"\nError: {e}")
        
        else:
            # ENCRYPTION
            text = get_input("\nEnter text to encrypt: ")
            
            max_length = None
            if get_yes_no("\nSet a character limit? (y/n): "):
                # Calculate minimum
                base_overhead = 4 + 16 + 32 + 32 + 24 + 32 + 48  # version + key_salt + L1-L5 headers
                text_bytes = len(text.encode('utf-8'))
                padded_len = text_bytes + (16 - (text_bytes % 16))
                min_raw = base_overhead + padded_len * 5  # rough expansion
                
                if mode == 'simple':
                    min_size = ((min_raw + 3) // 4) * 5
                    print(f"\nMinimum size (Base85): ~{min_size} characters")
                else:
                    min_size = min_raw
                    print(f"\nMinimum size (binary): ~{min_size} bytes")
                
                max_length_final = get_int(f"Enter limit (min ~{min_size}): ", min_val=min_size)
                
                if mode == 'simple':
                    max_length = 4 * (max_length_final // 5)
                else:
                    max_length = max_length_final
            
            try:
                encrypted_bytes = encrypt_text(text, passwords, max_length)
                
                # Always use Base85 for display (safe for terminals)
                display_output = _simple_encode(encrypted_bytes)
                
                if mode == 'simple':
                    final_output = display_output
                else:
                    final_output = encrypted_bytes
                
                if get_yes_no("\nShow encrypted output? (y/n): "):
                    pw_mode_str = "5-password" if multi_password else "master-password"
                    print(f"\nEncrypted ({mode}, {pw_mode_str}, 5 layers):")
                    print(display_output)  # Always show Base85
                
                if get_yes_no("\nSave to file? (y/n): "):
                    filename = get_input("Enter filename: ")
                    script_dir = os.path.dirname(os.path.abspath(__file__))
                    filepath = os.path.join(script_dir, filename)
                    
                    if mode == 'advanced':
                        with open(filepath, 'wb') as f:
                            f.write(final_output if isinstance(final_output, bytes) else final_output.encode('latin-1'))
                    else:
                        with open(filepath, 'w', encoding='utf-8') as f:
                            f.write(final_output)
                    print(f"Saved to: {filepath}")
                
            except Exception as e:
                print(f"\nError encrypting: {e}")
        
        print("\nDone!")
        
    except UserExit:
        print("\nExiting...")

if __name__ == "__main__":
    main()
