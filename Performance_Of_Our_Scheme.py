import numpy as np
import hashlib
import time
from tabulate import tabulate
import matplotlib.pyplot as plt

class LWE_Scheme:
    def __init__(self, n, m, q, mu=123):
        self.n = n
        self.m = m
        self.q = q
        self.mu = mu

    def hash_message(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        hash_digest = hashlib.sha256(data).digest()
        return int.from_bytes(hash_digest, 'big') % 19

    def check_linear_independence(self, A):
        rank = np.linalg.matrix_rank(A)
        if rank < min(A.shape):
            raise ValueError("Matrix A is not linearly independent. The program will terminate.")

    def check_small_norm(self, vector, threshold):
        norm = np.linalg.norm(vector)
        if norm >= threshold:
            raise ValueError(f"Vector {vector} is not a small norm vector (norm: {norm}).")

    def keygen(self):
        A = np.random.randint(0, self.q, size=(self.m, self.n))
        self.check_linear_independence(A)

        S = np.random.randint(0, self.q ** 0.05, size=self.n)
        E = np.random.randint(0, self.q ** 0.05, size=self.m)

        self.check_small_norm(S, threshold=self.q)
        self.check_small_norm(E, threshold=self.q)

        T = (A @ S + E) % self.q

        return (A, T), (S, E)

    def sign(self, A, S, E, message):
        y1 = np.random.randint(0, self.q ** 0.05, size=self.n)
        y2 = np.random.randint(0, self.q ** 0.05, size=self.m)

        self.check_small_norm(y1, threshold=self.q)
        self.check_small_norm(y2, threshold=self.q)

        v = (A @ y1 + y2) % self.q
        c = self.hash_message(message.encode('utf-8') + v.tobytes())
        z1 = (y1 + S * c) % self.q
        z2 = (y2 + E * c) % self.q

        return (z1, z2, c), (y1, y2, v)

    def verify(self, A, T, signature, message):
        z1, z2, c = signature
        v_prime = (A @ z1 + z2 - T * c) % self.q
        c_prime = self.hash_message(message.encode('utf-8') + v_prime.tobytes())
        return c == c_prime

# Generating table data and printing key sizes
table_data = []
times = []

for n in range(1000, 10001, 1000):
    q = 8383489  # A parameter set is proposed for scheme with 256 bits of security
    scheme = LWE_Scheme(n, n + 1, q)
    public_key, secret_keys = scheme.keygen()
    message = '123'
    # Perform the sign and verify multiple times for averaging
    num_iterations = 100
    total_sign_time = 0
    total_verify_time = 0

    for _ in range(num_iterations):
        start_sign_time = time.perf_counter()
        signature, intermediates = scheme.sign(public_key[0], *secret_keys, message)
        total_sign_time += (time.perf_counter() - start_sign_time)

        start_verify_time = time.perf_counter()
        verification_result = scheme.verify(public_key[0], public_key[1], signature, message)
        total_verify_time += (time.perf_counter() - start_verify_time)

    avg_sign_time = (total_sign_time / num_iterations) * 1000  # Convert to milliseconds
    avg_verify_time = (total_verify_time / num_iterations) * 1000  # Convert to milliseconds

    # Calculate the size of the keys and signature
    public_key_size = public_key[0].nbytes + public_key[1].nbytes
    secret_key_size = secret_keys[0].nbytes + secret_keys[1].nbytes
    signature_size = signature[0].nbytes + signature[1].nbytes + np.array(signature[2]).nbytes

    table_data.append([n, public_key_size, secret_key_size, signature_size, avg_sign_time, avg_verify_time])
    times.append([n, avg_sign_time + avg_verify_time])

    print(f"n={n} completed in {avg_sign_time + avg_verify_time:.6f} ms")

# Print the results in a tabulated format
print(tabulate(table_data, headers=["n", "Public Key Size (bytes)", "Secret Key Size (bytes)", "Signature Size (bytes)",
                                    "Avg Signing Time (ms)", "Avg Verification Time (ms)"], tablefmt="grid"))

# Plotting n vs. time
times = np.array(times)
plt.plot(times[:, 0], times[:, 1], marker='o')
plt.xlabel('n')
plt.ylabel('Time (ms)')
plt.title('n vs. Time')
plt.grid(True)
plt.show()
