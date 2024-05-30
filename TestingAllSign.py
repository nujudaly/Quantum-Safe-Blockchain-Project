from pqcrypto._sign.dilithium2 import ffi as __ffi2, lib as __lib2
from pqcrypto._sign.dilithium3 import ffi as __ffi3, lib as __lib3
from pqcrypto._sign.dilithium4 import ffi as __ffi4, lib as __lib4
from pqcrypto._sign.falcon_512 import ffi as __ffi512, lib as __lib512
from pqcrypto._sign.falcon_1024 import ffi as __ffi1024, lib as __lib1024
from pqcrypto._sign.sphincs_sha256_192f_simple import ffi as __ffi192f, lib as __lib192f  # Adjusted for SPHINCS+
from pqcrypto._sign.sphincs_sha256_256f_simple import ffi as __ffi, lib as __lib  # Adjusted for SPHINCS+
from pqcrypto.sign.common import (
    _sign_generate_keypair_factory,
    _sign_sign_factory,
    _sign_verify_factory,
)
import time
from ecdsa import SigningKey, NIST384p
import matplotlib.pyplot as plt


average_key_gen_times = [
    0.000191,  # Dilithium2
    0.000080,  # Dilithium3
    0.000130,  # Dilithium4
    0.000659,  # Falcon-512
    0.011353,  # Falcon-1024
    0.035209,  # SPHINCS+ SHA-256-192f
    0.001467,  # Placeholder (not specified)
    0.003976   # SPHINCS+ SHA-256-256f
]

average_signing_times = [
    0.000925,  # Dilithium2
    0.000100,  # Dilithium3
    0.000321,  # Dilithium4
    0.000313,  # Falcon-512
    0.003274,  # Falcon-1024
    0.006987,  # SPHINCS+ SHA-256-192f
    0.041881,  # Placeholder (not specified)
    0.092680   # SPHINCS+ SHA-256-256f
]

average_verification_times = [
    0.003721,  # Dilithium2
    0.000100,  # Dilithium3
    0.000060,  # Dilithium4
    0.000254,  # Falcon-512
    0.000040,  # Falcon-1024
    0.000060,  # SPHINCS+ SHA-256-192f
    0.002185,  # Placeholder (not specified)
    0.002095   # SPHINCS+ SHA-256-256f
]

# Define the schemes
schemes = ['ECDSA', 'Dilithium2', 'Dilithium3', 'Dilithium4', 'Falcon-512', 'Falcon-1024', 'SPHINCS+ SHA-256-192f', 'SPHINCS+ SHA-256-256f']

# Plotting the average times
# Define custom colors for the bars
colors = ['#4682B4', '#6F8FAF', '#0818A8']

fig, ax = plt.subplots(figsize=(14, 8))

bar_width = 0.20
index = range(len(schemes))

bar1 = ax.bar(index, average_key_gen_times, bar_width, label='Average key generation time', color=colors[0])
bar2 = ax.bar([i + bar_width for i in index], average_signing_times, bar_width, label='Average signing time', color=colors[1])
bar3 = ax.bar([i + 2 * bar_width for i in index], average_verification_times, bar_width, label='Average verification time', color=colors[2])

ax.set_xlabel('Signature Schemes')
ax.set_ylabel('Time (s * 10^-3)')
ax.set_title('Average (Key generation/signing/ verification) Times for Different Signature Schemes')
ax.set_xticks([i + bar_width for i in index])
ax.set_xticklabels(schemes, rotation=45, ha='right')
ax.legend()

# Set y-axis to logarithmic scale
ax.set_yscale('log')

plt.tight_layout()
plt.show()

def ecdsa_nist384p_generate_keypair():
    start_time = time.time()
    sk = SigningKey.generate(curve=NIST384p)
    vk = sk.verifying_key
    keypair_gen_time = time.time() - start_time
    #print(f"ECDSA NIST P-384 curve - Keypair generation time: {keypair_gen_time:.9f} seconds.")
    return vk, sk

def ecdsa_nist384p_sign(secret_key, message):
    start_time = time.time()
    signature = secret_key.sign(message)
    signing_time = time.time() - start_time
    #print(f"ECDSA NIST P-384 curve - Signing time: {signing_time:.9f} seconds.")
    return signature

def ecdsa_nist384p_verify(public_key, message, signature):
    start_time = time.time()
    is_valid = public_key.verify(signature, message)
    verification_time = time.time() - start_time
    #print(f"ECDSA NIST P-384 curve - Verification time: {verification_time:.9f} seconds.")
    return is_valid

# Define the sizes for ECDSA (NIST P-384 curve) signature scheme
ECDSA_NIST384P_PUBLIC_KEY_SIZE = len(ecdsa_nist384p_generate_keypair()[0].to_string())  # Size of the public key in bytes
ECDSA_NIST384P_SECRET_KEY_SIZE = len(ecdsa_nist384p_generate_keypair()[1].to_string())  # Size of the secret key in bytes
ECDSA_NIST384P_SIGNATURE_SIZE = len(ecdsa_nist384p_sign(ecdsa_nist384p_generate_keypair()[1], b"Nujud and Enas are the best!"))  # Size of the signature in bytes
# Constants - these might need to be adjusted if the schemes use different names
DILITHIUM2_PUBLIC_KEY_SIZE = __lib2.CRYPTO_PUBLICKEYBYTES
DILITHIUM2_SECRET_KEY_SIZE = __lib2.CRYPTO_SECRETKEYBYTES
DILITHIUM2_SIGNATURE_SIZE = __lib2.CRYPTO_BYTES

DILITHIUM3_PUBLIC_KEY_SIZE = __lib3.CRYPTO_PUBLICKEYBYTES
DILITHIUM3_SECRET_KEY_SIZE = __lib3.CRYPTO_SECRETKEYBYTES
DILITHIUM3_SIGNATURE_SIZE = __lib3.CRYPTO_BYTES

DILITHIUM4_PUBLIC_KEY_SIZE = __lib4.CRYPTO_PUBLICKEYBYTES
DILITHIUM4_SECRET_KEY_SIZE = __lib4.CRYPTO_SECRETKEYBYTES
DILITHIUM4_SIGNATURE_SIZE = __lib4.CRYPTO_BYTES

FALCON_512_PUBLIC_KEY_SIZE = __lib512.CRYPTO_PUBLICKEYBYTES
FALCON_512_SECRET_KEY_SIZE = __lib512.CRYPTO_SECRETKEYBYTES
FALCON_512_SIGNATURE_SIZE = __lib512.CRYPTO_BYTES

FALCON_1024_PUBLIC_KEY_SIZE = __lib1024.CRYPTO_PUBLICKEYBYTES
FALCON_1024_SECRET_KEY_SIZE = __lib1024.CRYPTO_SECRETKEYBYTES
FALCON_1024_SIGNATURE_SIZE = __lib1024.CRYPTO_BYTES

SPHINCS_SHA256_192F_PUBLIC_KEY_SIZE = __lib192f.CRYPTO_PUBLICKEYBYTES
SPHINCS_SHA256_192F_SECRET_KEY_SIZE = __lib192f.CRYPTO_SECRETKEYBYTES
SPHINCS_SHA256_192F_SIGNATURE_SIZE = __lib192f.CRYPTO_BYTES

SPHINCS_SHA256_256F_PUBLIC_KEY_SIZE = __lib.CRYPTO_PUBLICKEYBYTES
SPHINCS_SHA256_256F_SECRET_KEY_SIZE = __lib.CRYPTO_SECRETKEYBYTES
SPHINCS_SHA256_256F_SIGNATURE_SIZE = __lib.CRYPTO_BYTES

# Functions - these should work if the schemes have a similar API
dilithium2_generate_keypair = _sign_generate_keypair_factory(__ffi2, __lib2)
dilithium2_sign = _sign_sign_factory(__ffi2, __lib2)
dilithium2_verify = _sign_verify_factory(__ffi2, __lib2)

dilithium3_generate_keypair = _sign_generate_keypair_factory(__ffi3, __lib3)
dilithium3_sign = _sign_sign_factory(__ffi3, __lib3)
dilithium3_verify = _sign_verify_factory(__ffi3, __lib3)

dilithium4_generate_keypair = _sign_generate_keypair_factory(__ffi4, __lib4)
dilithium4_sign = _sign_sign_factory(__ffi4, __lib4)
dilithium4_verify = _sign_verify_factory(__ffi4, __lib4)

falcon_512_generate_keypair = _sign_generate_keypair_factory(__ffi512, __lib512)
falcon_512_sign = _sign_sign_factory(__ffi512, __lib512)
falcon_512_verify = _sign_verify_factory(__ffi512, __lib512)

falcon_1024_generate_keypair = _sign_generate_keypair_factory(__ffi1024, __lib1024)
falcon_1024_sign = _sign_sign_factory(__ffi1024, __lib1024)
falcon_1024_verify = _sign_verify_factory(__ffi1024, __lib1024)

sphincs_sha256_192f_generate_keypair = _sign_generate_keypair_factory(__ffi192f, __lib192f)
sphincs_sha256_192f_sign = _sign_sign_factory(__ffi192f, __lib192f)
sphincs_sha256_192f_verify = _sign_verify_factory(__ffi192f, __lib192f)

sphincs_sha256_256f_generate_keypair = _sign_generate_keypair_factory(__ffi, __lib)
sphincs_sha256_256f_sign = _sign_sign_factory(__ffi, __lib)
sphincs_sha256_256f_verify = _sign_verify_factory(__ffi, __lib)

# Define colors
public_key_color = '#4682B4'
secret_key_color = '#6F8FAF'

# Key sizes for each scheme
schemes = [
    "Dilithium2", "Dilithium3", "Dilithium4",
    "Falcon-512", "Falcon-1024",
    "SPHINCS+ SHA-256-192f", "SPHINCS+ SHA-256-256f",
    "ECDSA with NIST P-384 curve"
]
public_key_sizes = [
    DILITHIUM2_PUBLIC_KEY_SIZE, DILITHIUM3_PUBLIC_KEY_SIZE, DILITHIUM4_PUBLIC_KEY_SIZE,
    FALCON_512_PUBLIC_KEY_SIZE, FALCON_1024_PUBLIC_KEY_SIZE,
    SPHINCS_SHA256_192F_PUBLIC_KEY_SIZE, SPHINCS_SHA256_256F_PUBLIC_KEY_SIZE,
    ECDSA_NIST384P_PUBLIC_KEY_SIZE
]
secret_key_sizes = [
    DILITHIUM2_SECRET_KEY_SIZE, DILITHIUM3_SECRET_KEY_SIZE, DILITHIUM4_SECRET_KEY_SIZE,
    FALCON_512_SECRET_KEY_SIZE, FALCON_1024_SECRET_KEY_SIZE,
    SPHINCS_SHA256_192F_SECRET_KEY_SIZE, SPHINCS_SHA256_256F_SECRET_KEY_SIZE,
    ECDSA_NIST384P_SECRET_KEY_SIZE
]

# Plotting
fig, ax = plt.subplots()
bar_width = 0.35
index = range(len(schemes))

for i in index:
    ax.bar(i, public_key_sizes[i], bar_width, label='Public Key Size', color=public_key_color)
    ax.bar(i + bar_width, secret_key_sizes[i], bar_width, label='Secret Key Size', color=secret_key_color)

ax.set_xlabel('Signature Schemes')
ax.set_ylabel('Key Size (bytes)')
ax.set_title('Comparison of Key Sizes for Different Signature Schemes')
ax.set_xticks([i + bar_width / 2 for i in index])
ax.set_xticklabels(schemes, rotation=45, ha="right")

# Create custom legend with scheme names and colors
legend_elements = [
    plt.Line2D([0], [0], color=public_key_color, lw=4, label='Public Key Size'),
    plt.Line2D([0], [0], color=secret_key_color, lw=4, label='Secret Key Size')
]
ax.legend(handles=legend_elements, loc='upper left', title='Key Sizes')

plt.tight_layout()
plt.show()


schemes = [
    "ECDSA", "Dilithium2", "Dilithium3", "Dilithium4",
    "Falcon-512", "Falcon-1024", "SPHINCS+ SHA-256-192f", "SPHINCS+ SHA-256-256f"
]
security_levels = [192, 128, 192, 256, 128, 256, 128, 256]
security_types = [
    "Classical", "Post-Quantum", "Post-Quantum", "Post-Quantum",
    "Post-Quantum", "Post-Quantum", "Post-Quantum", "Post-Quantum"
]

# Define the colors for each security type
colors = {
    "Post-Quantum": '#4682B4',
    "Classical": '#6F8FAF'
}

# Plotting
plt.figure(figsize=(12, 6))
bars = []
for i, scheme in enumerate(schemes):
    bars.append(plt.bar(scheme, security_levels[i], color=colors[security_types[i]]))

# Add legend
legend_labels = ['Post-Quantum', 'Classical']
legend_handles = [plt.Rectangle((0,0),1,1, color=colors[label]) for label in legend_labels]
plt.legend(legend_handles, legend_labels, title='Security Type', loc='upper left')

plt.xlabel('Signature Schemes')
plt.ylabel('Security Level (bits)')
plt.title('Comparison of Security Levels for Different Signature Schemes')
plt.xticks(rotation=45, ha="right")

plt.tight_layout()
plt.show()

def test_signature_scheme(scheme_name, iterations, generate_keypair, sign, verify, public_key_size, secret_key_size, signature_size):
    total_keypair_gen_time = 0
    total_signing_time = 0
    total_verification_time = 0

    print(f"\nTesting {scheme_name} signature scheme:")
    print(f"Public key size: {public_key_size} bytes")
    print(f"Secret key size: {secret_key_size} bytes")
    print(f"Signature size: {signature_size} bytes")

    for i in range(iterations):
        # Measure keypair generation time
        start_time = time.time()
        public_key, secret_key = generate_keypair()
        keypair_gen_time = time.time() - start_time
        total_keypair_gen_time += keypair_gen_time
        #print(f"Iteration {i+1} - Keypair generation time: {keypair_gen_time:.9f} seconds.")

        # Define and hash a message
        message = b"Nujud and Enas are the best!"

        # Measure signing time
        start_time = time.time()
        signature = sign(secret_key, message)
        signing_time = time.time() - start_time
        total_signing_time += signing_time
        #print(f"Iteration {i+1} - Signing time: {signing_time:.9f} seconds.")

        # Measure verification time
        start_time = time.time()
        is_valid = verify(public_key, message, signature)
        verification_time = time.time() - start_time
        total_verification_time += verification_time
        #print(f"Iteration {i+1} - Verification time: {verification_time:.9f} seconds.")

    # Calculate the averages
    avg_keypair_gen_time = total_keypair_gen_time / iterations
    avg_signing_time = total_signing_time / iterations
    avg_verification_time = total_verification_time / iterations

    # Print the averages for this scheme
    print("\nAverage times for this scheme:")
    print(f"Average keypair generation time: {avg_keypair_gen_time:.6f} seconds.")
    print(f"Average signing time: {avg_signing_time:.6f} seconds.")
    print(f"Average verification time: {avg_verification_time:.6f} seconds.")


if __name__ == "__main__":
    iterations = 50  # Number of iterations to run the test

    # Test Dilithium2
    print("Testing Dilithium2 signature scheme:")
    test_signature_scheme(
        "Dilithium2",
        iterations,
        dilithium2_generate_keypair,
        dilithium2_sign,
        dilithium2_verify,
        DILITHIUM2_PUBLIC_KEY_SIZE,
        DILITHIUM2_SECRET_KEY_SIZE,
        DILITHIUM2_SIGNATURE_SIZE,
    )

    # Test Dilithium3
    print("\nTesting Dilithium3 signature scheme:")
    test_signature_scheme(
        "Dilithium3",
        iterations,
        dilithium3_generate_keypair,
        dilithium3_sign,
        dilithium3_verify,
        DILITHIUM3_PUBLIC_KEY_SIZE,
        DILITHIUM3_SECRET_KEY_SIZE,
        DILITHIUM3_SIGNATURE_SIZE,
    )

    # Test Dilithium4
    print("\nTesting Dilithium4 signature scheme:")
    test_signature_scheme(
        "Dilithium4",
        iterations,
        dilithium4_generate_keypair,
        dilithium4_sign,
        dilithium4_verify,
        DILITHIUM4_PUBLIC_KEY_SIZE,
        DILITHIUM4_SECRET_KEY_SIZE,
        DILITHIUM4_SIGNATURE_SIZE,
    )

    # Test Falcon-512
    print("\nTesting Falcon-512 signature scheme:")
    test_signature_scheme(
        "Falcon-512",
        iterations,
        falcon_512_generate_keypair,
        falcon_512_sign,
        falcon_512_verify,
        FALCON_512_PUBLIC_KEY_SIZE,
        FALCON_512_SECRET_KEY_SIZE,
        FALCON_512_SIGNATURE_SIZE,
    )

    # Test Falcon-1024
    print("\nTesting Falcon-1024 signature scheme:")
    test_signature_scheme(
        "Falcon-1024",
        iterations,
        falcon_1024_generate_keypair,
        falcon_1024_sign,
        falcon_1024_verify,
        FALCON_1024_PUBLIC_KEY_SIZE,
        FALCON_1024_SECRET_KEY_SIZE,
        FALCON_1024_SIGNATURE_SIZE,
    )

    # Test SPHINCS+ SHA-256-192f
    print("\nTesting SPHINCS+ SHA-256-192f signature scheme:")
    test_signature_scheme(
        "SPHINCS+ SHA-256-192f",
        iterations,
        sphincs_sha256_192f_generate_keypair,
        sphincs_sha256_192f_sign,
        sphincs_sha256_192f_verify,
        SPHINCS_SHA256_192F_PUBLIC_KEY_SIZE,
        SPHINCS_SHA256_192F_SECRET_KEY_SIZE,
        SPHINCS_SHA256_192F_SIGNATURE_SIZE,
    )

    # Test SPHINCS+ SHA-256-256f
    print("\nTesting SPHINCS+ SHA-256-256f signature scheme:")
    test_signature_scheme(
        "SPHINCS+ SHA-256-256f",
        iterations,
        sphincs_sha256_256f_generate_keypair,
        sphincs_sha256_256f_sign,
        sphincs_sha256_256f_verify,
        SPHINCS_SHA256_256F_PUBLIC_KEY_SIZE,
        SPHINCS_SHA256_256F_SECRET_KEY_SIZE,
        SPHINCS_SHA256_256F_SIGNATURE_SIZE,
    )

    # Test ECDSA with NIST P-384 curve
    print("\nTesting ECDSA with NIST P-384 curve signature scheme:")
    test_signature_scheme(
        "ECDSA with NIST P-384 curve",
        iterations,
        ecdsa_nist384p_generate_keypair,
        ecdsa_nist384p_sign,
        ecdsa_nist384p_verify,
        ECDSA_NIST384P_PUBLIC_KEY_SIZE,
        ECDSA_NIST384P_SECRET_KEY_SIZE,
        ECDSA_NIST384P_SIGNATURE_SIZE,
    )

