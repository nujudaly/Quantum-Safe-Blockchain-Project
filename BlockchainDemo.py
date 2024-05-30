import hashlib
import json
import sys
from time import time
from uuid import uuid4
import numpy as np
import requests
from flask import Flask, jsonify, request
import logging

logging.basicConfig(level=logging.DEBUG)

def hash_block(block):
    block_encoded = json.dumps(block, sort_keys=True).encode()
    return hashlib.sha256(block_encoded).hexdigest()


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

        return (z1, z2, c), (y1, y2, v)

    def verify(self, A, T, signature, message):
        z1, z2, c = signature
        v_prime = (A @ z1 + z2 - T * c) % self.q
        c_prime = self.hash_message(message.encode('utf-8') + v_prime.tobytes())
        is_verified = c == c_prime

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

class Blockchain:
    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.nodes = set()
        self.SimpleExampleLWE = LWE_Scheme(4, 5, 13, 123)  # Updated parameters to match the standalone test
        self.public_key, self.secret_keys = self.SimpleExampleLWE.keygen()  # Generate keys
        self.difficulty_target = '0000'
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = {
            'index': 0,
            'timestamp': time(),
            'transactions': [],
            'nonce': 0,
            'hash_of_previous_block': '0'
        }
        genesis_block['hash'] = hash_block(genesis_block)
        self.chain.append(genesis_block)
        logging.debug("Genesis block created: %s", genesis_block)

    def proof_of_work(self, index, hash_of_previous_block, transactions):
        nonce = 0
        while self.valid_proof(index, hash_of_previous_block, transactions, nonce) is False:
            nonce += 1
        return nonce

    def valid_proof(self, index, hash_of_previous_block, transactions, nonce):
        content = f'{index}{hash_of_previous_block}{transactions}{nonce}'.encode()
        content_hash = hashlib.sha256(content).hexdigest()
        return content_hash[:len(self.difficulty_target)] == self.difficulty_target

    def append_block(self, nonce, hash_of_previous_block):
        block = {
            'index': len(self.chain),
            'timestamp': time(),
            'transactions': self.current_transactions.copy(),
            'nonce': nonce,
            'hash_of_previous_block': hash_of_previous_block
        }
        self.current_transactions = []
        block['hash'] = hash_block(block)
        self.chain.append(block)
        logging.debug(f"New block appended: {block}")
        return block

    def add_transaction(self, sender, recipient, amount):
        message = f'{sender}{recipient}{amount}'
        signature, _ = self.SimpleExampleLWE.sign(self.public_key[0], self.secret_keys[0], self.secret_keys[1], message)
        z1, z2, c = signature
        transaction = {
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
            'signature': signature
        }
        self.current_transactions.append(transaction)
        logging.debug(f"Added transaction: {transaction}")
        logging.info(f"z1: {z1}, z2: {z2}")  # Output z1 and z2 to the terminal
        return transaction

    def verify_transaction_signature(self, transaction):
        z1, z2, c = transaction['signature']
        message = f'{transaction["sender"]}{transaction["recipient"]}{transaction["amount"]}'
        return self.SimpleExampleLWE.verify(self.public_key[0], self.public_key[1], z1, z2, c, message)

    @property
    def last_block(self):
        if len(self.chain) == 0:
            return None
        return self.chain[-1]

    def add_node(self, address):
        from urllib.parse import urlparse
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)
        logging.debug(f"Node added: {parsed_url.netloc}")

    def valid_chain(self, chain):
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            if block['hash_of_previous_block'] != hash_block(last_block):
                return False
            if not self.valid_proof(current_index, block['hash_of_previous_block'], block['transactions'], block['nonce']):
                return False
            last_block = block
            current_index += 1
        return True

    def update_blockchain(self):
        neighbours = self.nodes
        new_chain = None
        max_length = len(self.chain)

        for node in neighbours:
            response = requests.get(f'http://{node}/blockchain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        if new_chain:
            self.chain = new_chain
            return True
        return False

app = Flask(__name__)
node_identifier = str(uuid4()).replace('-', "")
blockchain = Blockchain()

@app.route('/blockchain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200

@app.route('/mine', methods=['GET'])
def mine_block():
    try:
        last_block = blockchain.last_block
        if last_block is None:
            return jsonify({'message': 'No last block found'}), 500

        last_block_hash = hash_block(last_block)
        index = len(blockchain.chain)
        nonce = blockchain.proof_of_work(index, last_block_hash, blockchain.current_transactions)
        block = blockchain.append_block(nonce, last_block_hash)

        response = {
            'message': "New Block Mined",
            'index': block['index'],
            'hash_of_previous_block': block['hash_of_previous_block'],
            'nonce': block['nonce'],
            'transactions': block['transactions'],
        }
        return jsonify(response), 200
    except Exception as e:
        logging.error("Error when trying to mine a block: %s", str(e))
        return jsonify({'message': 'Internal Server Error', 'error': str(e)}), 500

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()
    required_fields = ['sender', 'recipient', 'amount']
    if not all(k in values for k in required_fields):
        return jsonify({'message': 'Missing fields'}), 400
    transaction = blockchain.add_transaction(values['sender'], values['recipient'], values['amount'])
    z1, z2, c = transaction['signature']
    response = {
        'message': 'Transaction will be added to Block',
        'z1': z1.tolist(),
        'z2': z2.tolist(),
    }
    return jsonify(response), 201

@app.route('/transactions/get', methods=['GET'])
def get_transactions():
    logging.debug("Fetching current transactions")
    transactions = blockchain.current_transactions
    logging.debug(f"Current transactions: {transactions}")
    return jsonify(transactions), 200

@app.route('/nodes/add_nodes', methods=['POST'])
def add_nodes():
    values = request.get_json()
    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Missing node(s) info", 400
    for node in nodes:
        blockchain.add_node(node)
    response = {'message': 'New nodes added', 'nodes': list(blockchain.nodes), }
    return jsonify(response), 201

@app.route('/nodes/sync', methods=['GET'])
def sync():
    updated = blockchain.update_blockchain()
    if updated:
        response = {'message': 'The blockchain has been updated to the latest', 'blockchain': blockchain.chain}
    else:
        response = {'message': 'Our blockchain is the latest', 'blockchain': blockchain.chain}
    return jsonify(response), 200

if __name__ == '__main__':
    if len(sys.argv) == 2:
        try:
            port = int(sys.argv[1])
            app.run(host='0.0.0.0', port=port, debug=True)
        except ValueError:
            print("Invalid port number. Please provide a valid integer port number.")
    else:
        print("Please provide a port number as a command-line argument.")
