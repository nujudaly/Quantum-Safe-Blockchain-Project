from pqcrypto._kem.kyber512 import ffi as __ffi, lib as __lib
from pqcrypto.kem.common import _kem_generate_keypair_factory, _kem_encrypt_factory, _kem_decrypt_factory
import time

# Constants - adjust these to match Kyber's API if necessary
PUBLIC_KEY_SIZE = __lib.CRYPTO_PUBLICKEYBYTES
SECRET_KEY_SIZE = __lib.CRYPTO_SECRETKEYBYTES
CIPHERTEXT_SIZE = __lib.CRYPTO_CIPHERTEXTBYTES

# Functions - these should work with Kyber if it has a similar API to common KEM implementations
generate_keypair = _kem_generate_keypair_factory(__ffi, __lib)
encapsulate = _kem_encrypt_factory(__ffi, __lib)
decapsulate = _kem_decrypt_factory(__ffi, __lib)

def test_kyber_kem(iterations):
    total_keypair_gen_time = 0
    total_encapsulation_time = 0
    total_decapsulation_time = 0

    for i in range(iterations):
        # Measure keypair generation time
        start_time = time.time()
        public_key, secret_key = generate_keypair()
        keypair_gen_time = time.time() - start_time
        total_keypair_gen_time += keypair_gen_time
        print(f"Iteration {i+1} - Keypair generation time: {keypair_gen_time:.9f} seconds.")

        # Measure encapsulation time
        start_time = time.time()
        ciphertext, shared_secret_encaps = encapsulate(public_key)
        encapsulation_time = time.time() - start_time
        total_encapsulation_time += encapsulation_time
        print(f"Iteration {i+1} - Encapsulation time: {encapsulation_time:.9f} seconds.")

        # Measure decapsulation time
        start_time = time.time()
        shared_secret_decaps = decapsulate(secret_key, ciphertext)
        decapsulation_time = time.time() - start_time
        total_decapsulation_time += decapsulation_time
        print(f"Iteration {i+1} - Decapsulation time: {decapsulation_time:.9f} seconds.")

        # Check if the shared secrets match
        assert shared_secret_encaps == shared_secret_decaps, "Shared secrets do not match!"

    # Calculate the averages
    avg_keypair_gen_time = total_keypair_gen_time / iterations
    avg_encapsulation_time = total_encapsulation_time / iterations
    avg_decapsulation_time = total_decapsulation_time / iterations

    # Print the average times
    print("\nAverage times after all iterations:")
    print(f"Average keypair generation time: {avg_keypair_gen_time:.6f} seconds.")
    print(f"Average encapsulation time: {avg_encapsulation_time:.6f} seconds.")
    print(f"Average decapsulation time: {avg_decapsulation_time:.6f} seconds.")

if __name__ == "__main__":
    iterations = 100  # Adjust the number of iterations as needed
    test_kyber_kem(iterations)

# Print the default sizes for Kyber keys and ciphertext
print(f"Default Kyber secret key size: {SECRET_KEY_SIZE} bytes")
print(f"Default Kyber public key size: {PUBLIC_KEY_SIZE} bytes")
print(f"Default Kyber ciphertext size: {CIPHERTEXT_SIZE} bytes")
