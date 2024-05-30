from pqcrypto._sign.falcon_1024 import ffi as __ffi, lib as __lib
from pqcrypto.sign.common import _sign_generate_keypair_factory, _sign_sign_factory, _sign_verify_factory
import hashlib
import time

# Constants - these might need to be adjusted if FALCON uses different names
PUBLIC_KEY_SIZE = __lib.CRYPTO_PUBLICKEYBYTES
SECRET_KEY_SIZE = __lib.CRYPTO_SECRETKEYBYTES
SIGNATURE_SIZE = __lib.CRYPTO_BYTES

# Functions - these should work if FALCON has a similar API to Dilithium
generate_keypair = _sign_generate_keypair_factory(__ffi, __lib)
sign = _sign_sign_factory(__ffi, __lib)
verify = _sign_verify_factory(__ffi, __lib)

def test_falcon_signature(iterations):
    total_keypair_gen_time = 0
    total_signing_time = 0
    total_verification_time = 0

    for i in range(iterations):
        # Measure keypair generation time
        start_time = time.time()
        public_key, secret_key = generate_keypair()
        keypair_gen_time = time.time() - start_time
        total_keypair_gen_time += keypair_gen_time
        print(f"Iteration {i+1} - Keypair generation time: {keypair_gen_time:.9f} seconds.")

        # Define and hash a message
        message = b"Nujud and Enas are the best!"

        # Measure signing time
        start_time = time.time()
        signature = sign(secret_key, message)
        signing_time = time.time() - start_time
        total_signing_time += signing_time
        print(f"Iteration {i+1} - Signing time: {signing_time:.9f} seconds.")

        # Measure verification time
        start_time = time.time()
        is_valid = verify(public_key, message, signature)
        verification_time = time.time() - start_time
        total_verification_time += verification_time
        print(f"Iteration {i+1} - Verification time: {verification_time:.9f} seconds.")

    # Calculate the averages
    avg_keypair_gen_time = total_keypair_gen_time / iterations
    avg_signing_time = total_signing_time / iterations
    avg_verification_time = total_verification_time / iterations

    # Print the average times
    print("\nAverage times after all iterations:")
    print(f"Average keypair generation time: {avg_keypair_gen_time:.6f} seconds.")
    print(f"Average signing time: {avg_signing_time:.6f} seconds.")
    print(f"Average verification time: {avg_verification_time:.6f} seconds.")

if __name__ == "__main__":
    iterations = 100  # Number of iterations to run the test
    test_falcon_signature(iterations)

# Print the default secret key size for FALCON
print(f"Default FALCON secret key size: {SECRET_KEY_SIZE} bytes")
print(f"Default Public key size: {PUBLIC_KEY_SIZE} bytes")

