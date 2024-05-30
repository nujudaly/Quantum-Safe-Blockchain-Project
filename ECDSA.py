from ecdsa import SigningKey, VerifyingKey, NIST384p
import time
# Generate a signing key (private key)
sk = SigningKey.generate(curve=NIST384p)

# Generate the corresponding verifying key (public key)
vk = sk.verifying_key

# Generate a message to sign
message = b"Enas, Nujud!"

# Sign the message
signature = sk.sign(message)

# Verify the signature
is_valid = vk.verify(signature, message)

# Print the results
print("Signature:", signature.hex())
print("Signature is valid:", is_valid)




iterations = 100  # Number of iterations to run the test
total_key_generation_time = 0
total_signing_time = 0
total_verification_time = 0

for i in range(iterations):
    # Measure key generation time
    start_time = time.time()
    sk = SigningKey.generate(curve=NIST384p)
    vk = sk.verifying_key
    key_generation_time = time.time() - start_time
    total_key_generation_time += key_generation_time

    # Get the byte representation of the secret key and calculate its size in bits
    secret_key_bytes = sk.to_string()
    secret_key_size_bits = len(secret_key_bytes) * 8
    public_key_bytes = vk.to_string()
    public_key_size_bits = len(public_key_bytes) * 8


    print(f"Iteration {i+1}, Key generation time: {key_generation_time:.6f} seconds.")
    print(f"Iteration {i+1}, Secret key size: {secret_key_size_bits} bits.")

    # Measure signing time
    start_time = time.time()
    message = b"Enas, Nujud!"
    signature = sk.sign(message)
    signing_time = time.time() - start_time
    total_signing_time += signing_time
    print(f"Iteration {i+1}, Signing time: {signing_time:.6f} seconds.")

    # Measure verification time
    start_time = time.time()
    vk = sk.verifying_key
    is_valid = vk.verify(signature, message)
    verification_time = time.time() - start_time
    total_verification_time += verification_time
    print(f"Iteration {i+1}, Verification time: {verification_time:.6f} seconds.")
    print(f"Iteration {i+1}, Signature is valid: {is_valid}")

# Calculate the averages
avg_key_generation_time = total_key_generation_time / iterations
avg_signing_time = total_signing_time / iterations
avg_verification_time = total_verification_time / iterations


# Print the average times
print(f"Public key size: {public_key_size_bits} bits")

print(f"\nAverage key generation time: {avg_key_generation_time:.6f} seconds.")
print(f"Average signing time: {avg_signing_time:.6f} seconds.")
print(f"Average verification time: {avg_verification_time:.6f} seconds.")

