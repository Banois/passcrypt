# -*- coding: cp1252 -*-
# PassCrypt v5.3 - 5-Layer Encryption Tool
# Short Mode: compress_then_encrypt for compact printable output
import base64
import hashlib
import secrets
import hmac
import os
import getpass
import ctypes
from ctypes import wintypes
import gc
import time
import zlib
from typing import Tuple, List, Optional

# =============================================================================
# VERSION & CONSTANTS
# =============================================================================

VERSION = b'PC53'  # PassCrypt v5.3 format identifier

# =============================================================================
# INPUT HELPERS
# =============================================================================

class UserExit(Exception):
    """Raised when user types 'exit' to quit"""
    pass


class LegacyVersionError(ValueError):
    """Raised when a legacy tagged payload is detected in normal decrypt flow."""

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

def get_password_input(prompt: str, hide_input: bool) -> str:
    """Get password input, optionally hidden, with exit command support."""
    if not hide_input:
        return get_input(prompt)

    while True:
        try:
            value = getpass.getpass(prompt).strip()
        except Exception:
            print("Hidden password input is unavailable in this terminal. Falling back to visible input.")
            return get_input(prompt)

        if value.lower() == 'exit':
            raise UserExit()
        if value:
            return value
        print("Input cannot be empty. Type 'exit' to quit.")

# =============================================================================
# CLIPBOARD HELPERS
# =============================================================================

def copy_to_clipboard_private(text: str) -> bool:
    """
    Copy text to clipboard on Windows while requesting exclusion from clipboard
    history and cloud clipboard sync.
    """
    if os.name != 'nt':
        return False

    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32

    CF_UNICODETEXT = 13
    GMEM_MOVEABLE = 0x0002

    kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalLock.restype = wintypes.LPVOID
    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalUnlock.restype = wintypes.BOOL
    kernel32.GlobalFree.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalFree.restype = wintypes.HGLOBAL

    user32.OpenClipboard.argtypes = [wintypes.HWND]
    user32.OpenClipboard.restype = wintypes.BOOL
    user32.CloseClipboard.argtypes = []
    user32.CloseClipboard.restype = wintypes.BOOL
    user32.EmptyClipboard.argtypes = []
    user32.EmptyClipboard.restype = wintypes.BOOL
    user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    user32.SetClipboardData.restype = wintypes.HANDLE
    user32.RegisterClipboardFormatW.argtypes = [wintypes.LPCWSTR]
    user32.RegisterClipboardFormatW.restype = wintypes.UINT

    def _alloc_global(raw: bytes):
        handle = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(raw))
        if not handle:
            return None
        locked = kernel32.GlobalLock(handle)
        if not locked:
            kernel32.GlobalFree(handle)
            return None
        ctypes.memmove(locked, raw, len(raw))
        kernel32.GlobalUnlock(handle)
        return handle

    # Retry briefly in case clipboard is temporarily locked by another process.
    opened = False
    for _ in range(8):
        if user32.OpenClipboard(None):
            opened = True
            break
    if not opened:
        return False

    try:
        if not user32.EmptyClipboard():
            return False

        utf16 = text.encode('utf-16-le') + b'\x00\x00'
        text_handle = _alloc_global(utf16)
        if not text_handle:
            return False
        if not user32.SetClipboardData(CF_UNICODETEXT, text_handle):
            kernel32.GlobalFree(text_handle)
            return False

        # Request exclusion from clipboard history and cloud sync.
        for fmt_name in ("CanIncludeInClipboardHistory", "CanUploadToCloudClipboard"):
            fmt_id = user32.RegisterClipboardFormatW(fmt_name)
            if fmt_id:
                flag_handle = _alloc_global((0).to_bytes(4, 'little', signed=False))
                if flag_handle and not user32.SetClipboardData(fmt_id, flag_handle):
                    kernel32.GlobalFree(flag_handle)

        return True
    finally:
        user32.CloseClipboard()

def _wipe_bytearray(buf: Optional[bytearray]) -> None:
    """Best-effort in-place wipe for mutable byte buffers."""
    if not isinstance(buf, bytearray):
        return
    for i in range(len(buf)):
        buf[i] = 0
    buf.clear()

def _wipe_bytes_copy(buf: Optional[bytes]) -> None:
    """
    Best-effort wipe for immutable bytes by copying to a mutable buffer, wiping,
    then dropping references. Original immutable object cannot be guaranteed wiped.
    """
    if not isinstance(buf, bytes):
        return
    temp = bytearray(buf)
    _wipe_bytearray(temp)

def _wipe_password_list(passwords: Optional[List[str]]) -> None:
    """Best-effort overwrite and clear of password list references."""
    if not isinstance(passwords, list):
        return
    for i, pw in enumerate(passwords):
        if isinstance(pw, str) and pw:
            passwords[i] = '\0' * len(pw)
        else:
            passwords[i] = ''
    passwords.clear()

# =============================================================================
# KEY DERIVATION & AUTHENTICATION HELPERS
# =============================================================================

def _derive_key(password: str, salt: bytes, iterations: int = 100000) -> bytes:
    """Derive a cryptographic key from password using PBKDF2"""
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)

def _derive_layer_keys(master: str, salt: bytes) -> List[str]:
    """Derive all layer keys from a single master password using HKDF-like expansion"""
    master_key = _derive_key(master, salt, iterations=100000)
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
# LAYER 1..5 (unchanged)
# =============================================================================

# --- Layer 1
def layer1_encrypt(data: bytes, password: str) -> bytes:
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

# --- Layer 2
def layer2_encrypt(data: bytes, password: str) -> bytes:
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

# --- Layer 3
def _generate_sbox(key: bytes) -> Tuple[bytes, bytes]:
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

# --- Layer 4
def layer4_encrypt(data: bytes, password: str) -> bytes:
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

# --- Layer 5 (full)
def layer5_encrypt(data: bytes, password: str, max_length: int = None) -> bytes:
    if not data:
        return data
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(16)
    enc_key = _derive_key(password, salt, iterations=50000)
    transform_key = hashlib.sha256(enc_key + b'transform').digest()
    marker_key = hashlib.sha256(enc_key + b'markers').digest()
    hmac_key = hashlib.sha256(enc_key + b'hmac').digest()
    marker = marker_key[0]
    padding_len = 16 - (len(data) % 16)
    padded_data = data + bytes([padding_len] * padding_len)
    n = len(padded_data)
    perm = _create_permutation(transform_key, nonce, n)
    permuted = _apply_permutation(padded_data, perm)
    keystream = _generate_keystream(transform_key, nonce, n)
    encrypted = _xor_bytes(permuted, keystream)
    min_size = 48 + (n * 2)
    if max_length is not None and max_length < min_size:
        raise ValueError(f"max_length ({max_length}) too small. Minimum: {min_size}")
    result_bytes = bytearray()
    for i, byte_val in enumerate(encrypted):
        encoded_byte = byte_val ^ marker
        result_bytes.append(marker)
        result_bytes.append(encoded_byte)
        if i < n - 1:
            if max_length is not None:
                remaining_bytes = n - i - 1
                remaining_needed = remaining_bytes * 2
                space_left = max_length - 48 - len(result_bytes) - remaining_needed
                max_decoys = max(0, min(8, space_left))
            else:
                max_decoys = 8
            min_decoys = 1 if max_decoys > 0 else 0
            num_decoys = min_decoys + secrets.randbelow(max(1, max_decoys - min_decoys + 1)) if max_decoys > 0 else 0
            for _ in range(num_decoys):
                decoy = secrets.token_bytes(1)[0]
                while decoy == marker:
                    decoy = secrets.token_bytes(1)[0]
                result_bytes.append(decoy)
    hmac_sig = _hmac_sign(hmac_key, bytes(result_bytes))[:16]
    return salt + nonce + hmac_sig + bytes(result_bytes)

def layer5_decrypt(data: bytes, password: str) -> bytes:
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
    real_bytes = bytearray()
    i = 0
    while i < len(encrypted_data):
        if encrypted_data[i] == marker:
            if i + 1 < len(encrypted_data):
                real_bytes.append(encrypted_data[i + 1] ^ marker)
                i += 2
            else:
                i += 1
        else:
            i += 1
    if not real_bytes:
        raise ValueError("Decryption failed")
    n = len(real_bytes)
    keystream = _generate_keystream(transform_key, nonce, n)
    permuted = _xor_bytes(bytes(real_bytes), keystream)
    perm = _create_permutation(transform_key, nonce, n)
    unpadded = _reverse_permutation(permuted, perm)
    padding_len = unpadded[-1]
    if padding_len > 16 or padding_len == 0:
        raise ValueError("Decryption failed")
    if unpadded[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Decryption failed")
    return unpadded[:-padding_len]

# =============================================================================
# SHORT MODE: compress_then_encrypt (no enforced limit; aims to shorten)
# Compact header: salt(12) || nonce(8) || hmac(12) || ciphertext
# Output is base85 printable for easy copy/paste.
# =============================================================================

SHORT_SALT_LEN = 12
SHORT_NONCE_LEN = 8
SHORT_HMAC_LEN = 12  # 96-bit HMAC truncation (size vs security tradeoff)

def short_encrypt_bytes(plaintext: bytes, password: str, pbkdf2_iters: int = 100000) -> bytes:
    """Compress then encrypt to make short-mode outputs smaller for short inputs."""
    # compress first (zlib, max compression)
    compressed = zlib.compress(plaintext, level=9)
    salt = secrets.token_bytes(SHORT_SALT_LEN)
    nonce = secrets.token_bytes(SHORT_NONCE_LEN)
    key = _derive_key(password, salt, iterations=pbkdf2_iters)
    ks = _generate_keystream(key, nonce, len(compressed))
    ciphertext = _xor_bytes(compressed, ks)
    hmac_sig = _hmac_sign(key, nonce + ciphertext)[:SHORT_HMAC_LEN]
    return salt + nonce + hmac_sig + ciphertext

def short_decrypt_bytes(enc: bytes, password: str, pbkdf2_iters: int = 100000) -> bytes:
    """Decrypt short-mode (compress_then_encrypt) format."""
    min_header = SHORT_SALT_LEN + SHORT_NONCE_LEN + SHORT_HMAC_LEN
    if len(enc) < min_header:
        raise ValueError("Decryption failed")
    salt = enc[:SHORT_SALT_LEN]
    nonce = enc[SHORT_SALT_LEN:SHORT_SALT_LEN + SHORT_NONCE_LEN]
    stored_hmac = enc[SHORT_SALT_LEN + SHORT_NONCE_LEN:SHORT_SALT_LEN + SHORT_NONCE_LEN + SHORT_HMAC_LEN]
    ciphertext = enc[min_header:]
    key = _derive_key(password, salt, iterations=pbkdf2_iters)
    if not hmac.compare_digest(_hmac_sign(key, nonce + ciphertext)[:SHORT_HMAC_LEN], stored_hmac):
        raise ValueError("Decryption failed")
    ks = _generate_keystream(key, nonce, len(ciphertext))
    compressed = _xor_bytes(ciphertext, ks)
    # decompress
    try:
        plaintext = zlib.decompress(compressed)
    except Exception:
        raise ValueError("Decryption failed (decompress error)")
    return plaintext

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
# MAIN ENCRYPT/DECRYPT PIPELINES (unchanged)
# =============================================================================

def encrypt_text(text: str, passwords: List[str], max_length: int = None) -> bytes:
    key_salt = secrets.token_bytes(16)
    if len(passwords) == 1:
        layer_passwords = _derive_layer_keys(passwords[0], key_salt)
    elif len(passwords) == 5:
        layer_passwords = passwords
        key_salt = b'\x00' * 16
    else:
        raise ValueError("Must provide exactly 1 (master) or 5 (multi) passwords")
    data = text.encode('utf-8')
    data = layer1_encrypt(data, layer_passwords[0])
    data = layer2_encrypt(data, layer_passwords[1])
    data = layer3_encrypt(data, layer_passwords[2])
    data = layer4_encrypt(data, layer_passwords[3])
    data = layer5_encrypt(data, layer_passwords[4], max_length)
    return VERSION + key_salt + data

def decrypt_text(data: bytes, passwords: List[str]) -> bytes:
    """Decrypt current-version payload only."""
    if len(data) < 20:
        raise ValueError("Decryption failed")
    version = data[:4]
    if version != VERSION:
        raise LegacyVersionError("Legacy file detected")
    key_salt = data[4:20]
    encrypted = data[20:]
    if len(passwords) == 1:
        layer_passwords = _derive_layer_keys(passwords[0], key_salt)
    elif len(passwords) == 5:
        layer_passwords = passwords
    else:
        raise ValueError("Must provide exactly 1 (master) or 5 (multi) passwords")
    data = layer5_decrypt(encrypted, layer_passwords[4])
    data = layer4_decrypt(data, layer_passwords[3])
    data = layer3_decrypt(data, layer_passwords[2])
    data = layer2_decrypt(data, layer_passwords[1])
    data = layer1_decrypt(data, layer_passwords[0])
    return data

# =============================================================================
# MAIN CLI
# =============================================================================

def estimate_base85_len(byte_len: int) -> int:
    """Estimate Base85 final printable length (exact formula: 5 * ceil(byte_len / 4))"""
    return 5 * ((byte_len + 3) // 4)

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("PassCrypt v5.3 - 5-Layer Encryption Tool")
    print("=" * 60)
    print("Type 'exit' at any prompt to quit.\n")

    # Keep sensitive references in a small scope and scrub on exit.
    passwords: List[str] = []
    raw_data = None
    encrypted_bytes = None
    enc_bytes = None
    plaintext_bytes = None
    decrypted_buffer: Optional[bytearray] = None
    text = None
    final_output = None
    interrupted = False

    try:
        choice = get_choice("Enter 1 to encrypt or 2 to decrypt: ", ['1', '2'])
        print("\nChoose output mode:")
        print("  [1] simple  - Base85 printable of full 5-layer pipeline")
        print("  [2] advanced - binary file (full features, max security / size)")
        print("  [3] short   - compact printable 'writeable' mode (compress-then-encrypt)")
        mode_choice = get_choice("Enter mode (1= simple, 2= advanced, 3= short): ", ['1', '2', '3'])
        mode = 'simple' if mode_choice == '1' else ('advanced' if mode_choice == '2' else 'short')

        if choice == '2':
            # DECRYPTION
            while True:
                file_path = None
                try:
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
                        if mode == 'advanced':
                            with open(file_path, 'rb') as f:
                                raw_data = f.read()
                        else:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                raw_data = f.read().strip()
                        print(f"Loaded from: {file_path}")
                    else:
                        raw_data = get_input("Enter encrypted text: ")

                    pw_mode = get_choice("Enter 1 for single master password or 2 for 5 separate passwords: ", ['1', '2'])
                    multi_password = (pw_mode == '2')
                    show_chars = get_yes_no("Show decryption password characters while typing? (y/n): ")
                    hide_decrypt_password = not show_chars

                    if multi_password:
                        print("\nEnter 5 passwords (one for each layer):")
                        passwords = []
                        for i in range(1, 6):
                            pw = get_password_input(f'  Layer {i} password: ', hide_decrypt_password)
                            passwords.append(pw)
                    else:
                        passwords = [get_password_input("\nEnter master password: ", hide_decrypt_password)]

                    if mode == 'simple':
                        encrypted_bytes = _simple_decode(raw_data)
                        decrypted_bytes = decrypt_text(encrypted_bytes, passwords)
                    elif mode == 'short':
                        enc_bytes = _simple_decode(raw_data)
                        decrypted_bytes = short_decrypt_bytes(enc_bytes, passwords[0])
                    else:
                        encrypted_bytes = raw_data if isinstance(raw_data, bytes) else raw_data.encode('latin-1')
                        decrypted_bytes = decrypt_text(encrypted_bytes, passwords)

                    decrypted_buffer = bytearray(decrypted_bytes)
                    _wipe_bytes_copy(decrypted_bytes)
                    decrypted_bytes = b''

                    if get_yes_no("\nDo you want to access the decrypted output? (y/n): "):
                        show_mode = get_choice(
                            "Choose output: 1 = copy to clipboard, 2 = display in terminal: ",
                            ['1', '2']
                        )
                        if show_mode == '1':
                            text_view = decrypted_buffer.decode('utf-8', errors='replace')
                            if copy_to_clipboard_private(text_view):
                                print("Decrypted text copied to clipboard (clipboard history suppressed).")
                            else:
                                print("Clipboard copy failed.")
                            text_view = None
                        else:
                            text_view = decrypted_buffer.decode('utf-8', errors='replace')
                            print(f"\nDecrypted text:\n{text_view}")
                            text_view = None

                    if get_yes_no("\nSave to file? (y/n): "):
                        filename = get_input("Enter filename: ")
                        script_dir = os.path.dirname(os.path.abspath(__file__))
                        filepath = os.path.join(script_dir, filename)
                        text_view = decrypted_buffer.decode('utf-8', errors='replace')
                        with open(filepath, 'w', encoding='utf-8') as f:
                            f.write(text_view)
                        text_view = None
                        print(f"Saved to: {filepath}")
                    break

                except FileNotFoundError:
                    print(f"File not found: {file_path}")
                    if get_yes_no("Try again from file/text selection? (y/n): "):
                        continue
                    return
                except LegacyVersionError:
                    print("\nLegacy or invalid header detected.")
                    print("Warning: Changing the header may fail if the encryption process changed between versions.")
                    header_choice = get_choice(
                        "Choose: [1] replace file, [2] save to new location, [3] quit: ",
                        ['1', '2', '3']
                    )
                    if header_choice == '3':
                        return

                    if not isinstance(encrypted_bytes, bytes) or len(encrypted_bytes) < 4:
                        print("Unable to update header for this input.")
                        if get_yes_no("Try again from file/text selection? (y/n): "):
                            continue
                        return

                    patched_bytes = VERSION + encrypted_bytes[4:]
                    output_path = None

                    if header_choice == '1':
                        if not file_path:
                            print("Replace is only available when input is loaded from a file.")
                            header_choice = '2'
                        else:
                            output_path = file_path

                    if header_choice == '2':
                        path_choice = get_choice(
                            "Enter 1 to choose save path in file explorer or 2 to type path: ",
                            ['1', '2']
                        )
                        if path_choice == '1' and os.name == 'nt':
                            try:
                                import tkinter as tk
                                from tkinter import filedialog
                                print("\nOpening save dialog...")
                                root = tk.Tk()
                                root.withdraw()
                                root.attributes('-topmost', True)
                                if mode == 'advanced':
                                    output_path = filedialog.asksaveasfilename(
                                        title="Save header-updated file",
                                        defaultextension=".bin",
                                        filetypes=[("Binary files", "*.bin"), ("All files", "*.*")]
                                    )
                                else:
                                    output_path = filedialog.asksaveasfilename(
                                        title="Save header-updated file",
                                        defaultextension=".txt",
                                        filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
                                    )
                                root.destroy()
                                if not output_path:
                                    output_path = None
                            except Exception:
                                output_path = None
                        if not output_path:
                            output_path = get_input("Enter output file path: ")

                    try:
                        if mode == 'advanced':
                            with open(output_path, 'wb') as f:
                                f.write(patched_bytes)
                        else:
                            with open(output_path, 'w', encoding='utf-8') as f:
                                f.write(_simple_encode(patched_bytes))
                        print(f"Header updated and saved to: {output_path}")
                    except Exception as e:
                        print(f"Failed to save updated header file: {e}")
                    finally:
                        _wipe_bytes_copy(patched_bytes)
                        patched_bytes = None

                    if get_yes_no("Return to decrypt start? (y/n): "):
                        continue
                    return
                except ValueError:
                    print(f"\nDecryption failed. Check password and mode.")
                    if get_yes_no("Try again from file/text selection? (y/n): "):
                        continue
                    return
                except Exception as e:
                    print(f"\nError: {e}")
                    if get_yes_no("Try again from file/text selection? (y/n): "):
                        continue
                    return
                finally:
                    _wipe_password_list(passwords)
                    passwords = []
                    if isinstance(raw_data, bytes):
                        _wipe_bytes_copy(raw_data)
                    raw_data = None
                    if isinstance(encrypted_bytes, bytes):
                        _wipe_bytes_copy(encrypted_bytes)
                    encrypted_bytes = None
                    if isinstance(enc_bytes, bytes):
                        _wipe_bytes_copy(enc_bytes)
                    enc_bytes = None
                    _wipe_bytearray(decrypted_buffer)
                    decrypted_buffer = None

        else:
            # ENCRYPTION
            pw_mode = get_choice("Enter 1 for single master password or 2 for 5 separate passwords: ", ['1', '2'])
            multi_password = (pw_mode == '2')
            show_chars = get_yes_no("Show encryption password characters while typing? (y/n): ")
            hide_encrypt_password = not show_chars

            # Collect passwords
            if multi_password:
                print("\nEnter 5 passwords (one for each layer):")
                passwords = []
                for i in range(1, 6):
                    pw = get_password_input(f'  Layer {i} password: ', hide_encrypt_password)
                    passwords.append(pw)
            else:
                passwords = [get_password_input("\nEnter master password: ", hide_encrypt_password)]

            text = get_input("\nEnter text to encrypt: ")

            if mode == 'short':
                # Compress-then-encrypt; do not enforce a short numeric limit or show estimate.
                plaintext_bytes = text.encode('utf-8')
                enc_bytes = short_encrypt_bytes(plaintext_bytes, passwords[0])
                display_output = _simple_encode(enc_bytes)
                final_output = display_output
            else:
                # full pipeline (simple or advanced)
                max_length = None
                if get_yes_no("\nSet a character/byte limit? (y/n): "):
                    base_overhead = 4 + 16 + 32 + 32 + 24 + 32 + 48  # rough
                    text_bytes = len(text.encode('utf-8'))
                    padded_len = text_bytes + (16 - (text_bytes % 16))
                    min_raw = base_overhead + padded_len * 5
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
                encrypted_bytes = encrypt_text(text, passwords, max_length)
                display_output = _simple_encode(encrypted_bytes)
                final_output = display_output if mode == 'simple' else encrypted_bytes

            if get_yes_no("\nShow encrypted output? (y/n): "):
                pw_mode_str = "5-password" if multi_password else "master-password"
                print(f"\nEncrypted ({mode}, {pw_mode_str}):")
                if isinstance(final_output, bytes):
                    print(_simple_encode(final_output))
                else:
                    print(final_output)

            if get_yes_no("\nSave to file? (y/n): "):
                filename = get_input("Enter filename: ")
                script_dir = os.path.dirname(os.path.abspath(__file__))
                filepath = os.path.join(script_dir, filename)
                try:
                    if mode == 'advanced':
                        with open(filepath, 'wb') as f:
                            f.write(final_output if isinstance(final_output, bytes) else final_output.encode('latin-1'))
                    else:
                        with open(filepath, 'w', encoding='utf-8') as f:
                            f.write(final_output)
                    print(f"Saved to: {filepath}")
                except Exception as e:
                    print(f"Error saving file: {e}")

        print("\nDone!")

    except UserExit:
        print("\nExiting...")
    except KeyboardInterrupt:
        interrupted = True
        print("\nInterrupted. Clearing now...")
    finally:
        _wipe_password_list(passwords)
        passwords = []

        if isinstance(raw_data, bytes):
            _wipe_bytes_copy(raw_data)
        raw_data = None

        if isinstance(encrypted_bytes, bytes):
            _wipe_bytes_copy(encrypted_bytes)
        encrypted_bytes = None

        if isinstance(enc_bytes, bytes):
            _wipe_bytes_copy(enc_bytes)
        enc_bytes = None

        if isinstance(plaintext_bytes, bytes):
            _wipe_bytes_copy(plaintext_bytes)
        plaintext_bytes = None

        _wipe_bytearray(decrypted_buffer)
        decrypted_buffer = None

        text = None
        final_output = None
        gc.collect()

        if not interrupted:
            print("\nClearing in 3 seconds...")
            time.sleep(3)
        os.system('cls' if os.name == 'nt' else 'clear')

if __name__ == "__main__":
    main()
