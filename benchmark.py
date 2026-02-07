import subprocess
import re
import os
from decimal import Decimal, getcontext

#  precision for Decimal math to ensure we don't lose bits during ms -> s conversion
getcontext().prec = 20

# config
PROJECT_DIR = os.path.expanduser("~/programming/rlwe3/rlwe_project")
CARGO_CMD = ["cargo", "run", "--release", "--quiet"]
PLAINTEXT_FILE = "plaintext.txt"
ITERATIONS = 100
KEY_SIZE_BYTES = 32

def generate_openssl_key(n_bytes):
    result = subprocess.run(
        ["openssl", "rand", "-hex", str(n_bytes)],
        capture_output=True, text=True, check=True
    )
    return result.stdout.strip()

def run_rlwe_cycle():
    # Sequence: 1 (Keygen), 2 (Encrypt), 3 (Decrypt), 4 (Exit)
    input_sequence = "1\n2\n3\n4\n"
    process = subprocess.Popen(
        CARGO_CMD,
        cwd=PROJECT_DIR,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    stdout, _ = process.communicate(input=input_sequence)
    return stdout

def extract_times_as_seconds(output):
    """
    Finds 'Time taken: X.XXX ms', converts to decimal seconds
    """
    # Regex captures the digits regardless of how many decimal places Rust prints
    matches = re.findall(r"Time taken: ([\d.]+) ms", output)
    if len(matches) >= 3:
        return {
            "keygen":  Decimal(matches[0]) / Decimal('1000'),
            "encrypt": Decimal(matches[1]) / Decimal('1000'),
            "decrypt": Decimal(matches[2]) / Decimal('1000')
        }
    return None

enc_results = []
dec_results = []

print(f"--- Starting High-Precision Benchmark ({ITERATIONS} iterations) ---")

for i in range(ITERATIONS):
    # Prepare plaintext
    new_key = generate_openssl_key(KEY_SIZE_BYTES)
    with open(os.path.join(PROJECT_DIR, PLAINTEXT_FILE), "w") as f:
        f.write(new_key)
    
    # Execute
    output = run_rlwe_cycle()
    times = extract_times_as_seconds(output)
    
    if times:
        enc_results.append(times['encrypt'])
        dec_results.append(times['decrypt'])
        print(f"Iteration {i+1} complete.")
    else:
        print(f"Iteration {i+1}: Failed to parse output.")

# final resutls
def print_results(label, data):
    print(f"\n{label} (seconds):")
    print("-" * 30)
    for val in data:
        # format to like 12 decimal places
        print(f"{val:.12f}")

print_results("ENCRYPTION TIMES", enc_results)
print_results("DECRYPTION TIMES", dec_results)

if enc_results:
    avg_enc = sum(enc_results) / len(enc_results)
    avg_dec = sum(dec_results) / len(dec_results)
    print("\n" + "="*30)
    print(f"AVG ENCRYPT: {avg_enc:.12f} s")
    print(f"AVG DECRYPT: {avg_dec:.12f} s")