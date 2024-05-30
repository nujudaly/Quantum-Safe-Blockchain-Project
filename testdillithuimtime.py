from pqcrypto.sign.dilithium2 import ffi as __ffi, lib as __lib
from pqcrypto.sign.common import _sign_generate_keypair_factory, _sign_sign_factory, _sign_verify_factory
import hashlib
import time

# Constants
PUBLIC_KEY_SIZE = __lib.CRYPTO_PUBLICKEYBYTES
SECRET_KEY_SIZE = __lib.CRYPTO_SECRETKEYBYTES
SIGNATURE_SIZE = __lib.CRYPTO_BYTES

# Functions
generate_keypair = _sign_generate_keypair_factory(__ffi, __lib)
sign = _sign_sign_factory(__ffi, __lib)
verify = _sign_verify_factory(__ffi, __lib)

def test_dilithium_signature():
    # Measure keypair generation time
    start_time = time.time()
    public_key, secret_key = generate_keypair()
    keypair_gen_time = time.time() - start_time
    print(f"Keypair generation took: {keypair_gen_time:.6f} seconds.")

    # Define and hash a message
    message = b"Nujud and Enas are the best!"
    hashed_message = hashlib.sha256(message).hexdigest()
    print(f"Message after hashing: {hashed_message}")

    # Measure signing time
    start_time = time.time()
    signature = sign(secret_key, message)
    signing_time = time.time() - start_time
    print(f"Signing took: {signing_time:.6f} seconds. Signature: {signature.hex()}")

    # Measure verification time
    start_time = time.time()
    is_valid = verify(public_key, message, signature)
    verification_time = time.time() - start_time
    print(f"Verification took: {verification_time:.6f} seconds.")
    print(f"Original message for verification: {message.decode()}")
    print(f"Verification result: {'valid' if is_valid else 'invalid'}")

if __name__ == "__main__":
    test_dilithium_signature()
