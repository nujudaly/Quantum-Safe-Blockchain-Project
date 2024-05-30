import numpy as np
import hashlib
import time

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