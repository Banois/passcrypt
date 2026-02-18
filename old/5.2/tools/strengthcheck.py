#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PassCrypt v5.2 — REAL Brute-Force Time Calculator (fixed)
> Accurate charset detection and path-aware PBKDF2 cost per layer.
> This is an ESTIMATOR only. It does NOT attempt to decrypt or crack anything.
"""

import string
from decimal import Decimal, getcontext, InvalidOperation

# increase precision for very large numbers
getcontext().prec = 80

# ---------------------------
# Attacker performance models
# ---------------------------
ATTACKERS = {
    "1": ("CPU (≈5k PBKDF2 guesses/sec)", Decimal(5_000)),
    "2": ("GPU (≈100k PBKDF2 guesses/sec)", Decimal(100_000)),
    "3": ("High-end rig (≈500k PBKDF2 guesses/sec)", Decimal(500_000))
}

# ---------------------------
# PBKDF2 iteration counts (from PassCrypt v5.2)
# ---------------------------
LAYER_PBKDF2 = {
    1: 10_000,   # layer1
    2: 15_000,   # layer2
    3: 20_000,   # layer3
    4: 25_000,   # layer4
    5: 50_000    # layer5
}
MASTER_PBKDF2 = 100_000   # when using a single master password or short-mode

# ---------------------------
# Helper: Charset detection (FIXED)
# ---------------------------
def detect_charset_size(password: str) -> (int, str):
    """
    Determine the *attacker's assumed* charset size based on the characters present.
    Rules:
    - If any whitespace or punctuation present => assume full printable ASCII (95).
    - Otherwise, combinations:
        digits only -> 10
        lowercase only -> 26
        uppercase only -> 26
        lowercase+uppercase -> 52
        lowercase+digits -> 36
        uppercase+digits -> 36
        lowercase+uppercase+digits -> 62
    - Default fallback => 95
    Returns (charset_size, description)
    """
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    # consider punctuation and whitespace as "other"
    has_other = any((c in string.punctuation) or c.isspace() for c in password)

    if has_other:
        return 95, "printable ASCII (space + punctuation + digits + letters) - conservative"
    if has_lower and has_upper and has_digit:
        return 62, "alphanumeric (lower+upper+digits)"
    if has_lower and has_upper:
        return 52, "letters (lower+upper)"
    if has_lower and has_digit:
        return 36, "lowercase + digits"
    if has_upper and has_digit:
        return 36, "uppercase + digits"
    if has_lower:
        return 26, "lowercase only"
    if has_upper:
        return 26, "uppercase only"
    if has_digit:
        return 10, "digits only"
    # fallback
    return 95, "printable ASCII (fallback)"

# ---------------------------
# Helper: format huge durations
# ---------------------------
SECONDS_PER_YEAR = Decimal(60 * 60 * 24 * 365)

def format_duration(seconds_dec: Decimal) -> str:
    """Return readable duration. If huge, use scientific notation for years."""
    if seconds_dec < 0:
        return "N/A"

    years = seconds_dec / SECONDS_PER_YEAR

    # small durations -> human friendly
    if years < Decimal("0.0001"):
        # show in appropriate smaller units
        secs = seconds_dec
        if secs < 60:
            return f"{secs:.2f} seconds"
        mins = secs / Decimal(60)
        if mins < 60:
            return f"{mins:.2f} minutes"
        hrs = mins / Decimal(60)
        if hrs < 24:
            return f"{hrs:.2f} hours"
        days = hrs / Decimal(24)
        return f"{days:.4f} days"
    # moderate durations -> show years with thousand separators
    if years < Decimal("1e6"):
        # show with comma grouping
        try:
            years_int = int(years.to_integral_value(rounding='ROUND_HALF_UP'))
            # if fractional years are meaningful, show 2 decimal places
            frac = years - Decimal(years_int)
            if frac == 0:
                return f"{years_int:,} years"
            else:
                yr_float = float(years)
                return f"{yr_float:,.2f} years"
        except (OverflowError, InvalidOperation):
            pass
    # very large -> scientific notation
    try:
        return f"{format(years, '.3E')} years"
    except Exception:
        # fallback
        return f"{str(years)} years"

# ---------------------------
# Core brute-force math
# ---------------------------
def compute_attempts(charset_size: int, length: int) -> int:
    """Total number of combinations (charset_size ** length). Returns Python int (big)."""
    return pow(charset_size, length)

def compute_time_for_attempts(attempts: int, pbkdf2_iters: int, attacker_speed: Decimal) -> (Decimal, Decimal):
    """
    Compute average and worst-case durations (as Decimals) given:
    - attempts (int)
    - pbkdf2_iters (int) required per guess for that password
    - attacker_speed (guesses/sec) calibrated to PBKDF2 at 100k iterations:
        We assume attacker_speed equals guesses/sec when each guess costs 100k PBKDF2 iterations.
        If pbkdf2_iters differs, scale speed proportionally:
            effective_speed = attacker_speed * (100000 / pbkdf2_iters)
    Returns (average_seconds_decimal, worst_seconds_decimal)
    """
    if attempts <= 0:
        return Decimal(0), Decimal(0)

    # convert to Decimal
    attempts_dec = Decimal(attempts)
    # scale attacker speed by iterations
    effective_speed = attacker_speed * (Decimal(MASTER_PBKDF2) / Decimal(pbkdf2_iters))
    if effective_speed <= 0:
        raise ValueError("Invalid attacker speed scaling")

    worst_seconds = attempts_dec / effective_speed
    average_seconds = worst_seconds / Decimal(2)
    return average_seconds, worst_seconds

# ---------------------------
# Interactive CLI (flows like original)
# ---------------------------
def get_choice(prompt: str, choices: list) -> str:
    while True:
        val = input(prompt).strip()
        if val in choices:
            return val
        print(f"Invalid choice. Enter one of: {', '.join(choices)}")

def get_nonempty(prompt: str) -> str:
    while True:
        v = input(prompt).strip()
        if v:
            return v
        print("Input cannot be empty.")

def main():
    print("PassCrypt v5.2 – REAL Brute-Force Time Calculator (fixed)")
    print("=" * 65)
    print("This tool estimates how long a pure brute-force search would take")
    print("to *reach the exact password* you provide. It does NOT crack or decrypt.\n")

    encrypted_text = get_nonempty("Paste encrypted text (as-is): ")

    print("\nWhich mode was used?")
    print("  [1] simple")
    print("  [2] advanced")
    print("  [3] short")
    mode_choice = get_choice("Enter choice: ", ['1', '2', '3'])
    mode = "short" if mode_choice == '3' else "full"

    print("\nPassword configuration:")
    print("  [1] Single master password")
    print("  [2] 5 separate passwords")
    pw_choice = get_choice("Enter choice: ", ['1', '2'])
    pw_mode = "master" if pw_choice == '1' else "five"

    passwords = []
    if pw_mode == "master":
        pw = get_nonempty("\nEnter master password: ")
        passwords.append(pw)
    else:
        print("\nEnter the 5 passwords (Layer 1..5 in order):")
        for i in range(1, 6):
            pw = get_nonempty(f"  Layer {i} password: ")
            passwords.append(pw)

    print("\nAttacker capability:")
    for k, (desc, _) in ATTACKERS.items():
        print(f"  [{k}] {desc}")
    atk_choice = get_choice("Enter choice: ", list(ATTACKERS.keys()))
    attacker_desc, attacker_speed = ATTACKERS[atk_choice]

    print("\nRESULTS")
    print("=" * 65)
    print(f"Mode chosen: {'short' if mode == 'short' else 'full 5-layer pipeline'}")
    print(f"Password configuration: {'single master' if pw_mode == 'master' else '5 separate passwords'}")
    print(f"Assumed attacker: {attacker_desc}\n")

    per_pw_results = []
    total_avg_seq = Decimal(0)
    total_worst_seq = Decimal(0)

    # For each password, determine appropriate pbkdf2 iteration cost
    for idx, pw in enumerate(passwords, start=1):
        # determine PBKDF2 iterations for this guess
        if mode == 'short' or pw_mode == 'master':
            iterations = MASTER_PBKDF2
        else:
            # five-password mode: choose specific layer's iteration count
            layer = idx
            iterations = LAYER_PBKDF2.get(layer, MASTER_PBKDF2)

        length = len(pw)
        charset_size, charset_desc = detect_charset_size(pw)
        attempts = compute_attempts(charset_size, length)
        avg_seconds, worst_seconds = compute_time_for_attempts(attempts, iterations, attacker_speed)

        per_pw_results.append({
            "index": idx,
            "password": pw,
            "length": length,
            "charset_size": charset_size,
            "charset_desc": charset_desc,
            "attempts": attempts,
            "iterations": iterations,
            "avg_seconds": avg_seconds,
            "worst_seconds": worst_seconds
        })

        total_avg_seq += avg_seconds
        total_worst_seq += worst_seconds

        # print per-password
        print(f"Password {idx}:")
        print(f"  Length: {length}")
        print(f"  Charset assumption: {charset_desc} (size={charset_size})")
        print(f"  PBKDF2 iterations per guess (this layer): {iterations:,}")
        print(f"  Attempts needed (charset^length): {attempts:,}")
        print(f"  Average time to reach this password: {format_duration(avg_seconds)}")
        print(f"  Worst-case time to reach this password: {format_duration(worst_seconds)}")
        print("-" * 60)

    # Sequential model: attacker finds each password one after another (independent searches)
    if len(per_pw_results) > 1:
        print("\nTOTAL (sequential model — attacker finds each layer/password individually):")
        print(f"  Average total time (sum of averages): {format_duration(total_avg_seq)}")
        print(f"  Worst total time   (sum of worst-cases): {format_duration(total_worst_seq)}")

        # Joint model: attacker must guess the entire combination (cartesian product)
        # This is the 'product of attempts' model: attempts_product = Π attempts_i
        attempts_product = 1
        for r in per_pw_results:
            attempts_product *= r["attempts"]

        # For joint model, we need an effective PBKDF2 iterations per joint guess.
        # In the worst conservative view, the attacker needs to perform guesses that test
        # all layers => each joint guess implies running PBKDF2 for each layer. We take sum of iterations.
        joint_iterations = 0
        for idx, r in enumerate(per_pw_results, start=1):
            # use the iterations for the corresponding layer
            if mode == 'short' or (pw_mode == 'master' and idx == 1):
                joint_iterations += MASTER_PBKDF2
            else:
                joint_iterations += LAYER_PBKDF2.get(idx, MASTER_PBKDF2)

        # compute joint times (average & worst)
        joint_avg_sec, joint_worst_sec = compute_time_for_attempts(attempts_product, joint_iterations, attacker_speed)

        print("\nTOTAL (joint model — attacker brute-forces whole combination at once):")
        print(f"  Attempts (product of per-password attempts): {attempts_product:,}")
        print(f"  PBKDF2 iterations per joint guess (sum of per-layer iters): {joint_iterations:,}")
        print(f"  Average total time (joint search): {format_duration(joint_avg_sec)}")
        print(f"  Worst total time   (joint search): {format_duration(joint_worst_sec)}")
    else:
        print("\nSingle password provided — totals are the same as the per-password values above.")

    print("\nNotes:")
    print("- This is PURE brute-force modelling (no dictionaries, rules, or heuristics).")
    print("- Charset assumptions are conservative: any punctuation/space => printable ASCII (95).")
    print("- 'Sequential' sums times to find each password individually; 'Joint' models a full combination search.")
    print("- No cracking or decryption is performed by this tool.")

if __name__ == "__main__":
    main()
