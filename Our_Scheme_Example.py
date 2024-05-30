import numpy as np
import hashlib

class LWE_Scheme:
    def __init__(self, n, m, q, mu):
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
        # Check if the matrix A is linearly independent
        rank = np.linalg.matrix_rank(A)
        if rank < min(A.shape):
            raise ValueError("Matrix A is not linearly independent. The program will terminate.")

    def check_small_norm(self, vector, threshold):
        norm = np.linalg.norm(vector)
        if norm >= threshold:
            raise ValueError(f"Vector {vector} is not a small norm vector (norm: {norm}).")

    def keygen(self):

        A = np.array([[4, 2, 10, 5],
                      [0, 8, 7, 9],
                      [3, 0, 0, 4],
                      [10, 10, 2, 7],
                      [12, 10, 7, 4]])

        # Check if A is linearly independent
        self.check_linear_independence(A)

        S = np.array([1, 1, 1, 0])
        E = np.array([2, 0, 0, 1, 0])

        # Check if S and E are small norm vectors
        self.check_small_norm(S, threshold=self.q)
        self.check_small_norm(E, threshold=self.q)

        T = (A @ S + E) % self.q

        print("\nGenerated Public Key (A, T):")
        print("A:")
        print(A)
        print("T:")
        print(T)

        print("\nGenerated Secret Keys (S, E):")
        print("S:")
        print(S)
        print("E:")
        print(E)

        return (A, T), (S, E)

    def sign(self, A, S, E, message):
        y1 = np.array([0, 0, 2, 1])
        y2 = np.array([2, 0, 2, 1, 2])
        # Check if y1 and y2 are small norm vectors
        self.check_small_norm(y1, threshold=self.q)
        self.check_small_norm(y2, threshold=self.q)

        v = (A @ y1 + y2) % self.q
        c = self.hash_message(message.encode('utf-8') + v.tobytes())
        z1 = (y1 + S * c) % self.q
        z2 = (y2 + E * c) % self.q


        print("\nGenerated Signature (z1, z2, c):")
        print("z1:")
        print(z1)
        print("z2:")
        print(z2)
        print("c:")
        print(c)

        return (z1, z2, c), (y1, y2, v)

    def verify(self, A, T, signature, message):
        z1, z2, c = signature
        v_prime = (A @ z1 + z2 - T * c) % self.q
        c_prime = self.hash_message(message.encode('utf-8') + v_prime.tobytes())
        is_verified = c == c_prime

        print("\nVerification Result:")
        print("Computed c_prime:")
        print(c_prime)
        print("Given c:")
        print(c)
        print("Are they equal? (Should be True for successful verification):")
        print(is_verified)

        return is_verified

# Testing the modified scheme
try:
    scheme = LWE_Scheme(4, 5, 13, 123)
    public_key, secret_keys = scheme.keygen()
    message = 'address1address210'  # Consistent message
    signature, _ = scheme.sign(public_key[0], secret_keys[0], secret_keys[1], message)
    is_verified = scheme.verify(public_key[0], public_key[1], signature, message)
except ValueError as e:
    print(e)
