import hashlib
import hmac
import secrets
from typing import List, Tuple
import numpy as np

class NTTEngine:
    """Handles Radix-3 Number Theoretic Transform (NTT) operations over GF(p)."""
    def __init__(self, p:int=17497, n: int=2187) -> None:
        self.p = p
        self.n = n
        self.omega = 4
        self.root1 = 12777 # Primitive 3rd root of unity mod p
        self.root2 = 4719  # Primitive 3rd root of unity mod p

    def transform(self, vector: np.ndarray) -> np.ndarray:
        """Executes a full Radix-3 Cooley-Tukey NTT forward transform."""
        v_len = len(vector)
        transformed = np.pad(vector, (0, self.n - v_len), 'constant').astype(np.uint64) if v_len < self.n else vector[:self.n].astype(np.uint64)
        
        for stage in range(1, 8):
            length = 3**stage
            step = length // 3
            w_base = pow(self.omega, self.n // length, self.p)
            for i in range(0, self.n, length):
                for j in range(step):
                    w = pow(w_base, j, self.p)
                    w2 = (w*w) % self.p
                    t0 = transformed[i + j]
                    t1 = (transformed[i + j + step] * w) % self.p
                    t2 = (transformed[i + j + 2*step] * w2) % self.p
                    
                    transformed[i + j] = (t0 + t1 + t2) % self.p
                    transformed[i + j + step] = (t0 + t1 * self.root1 + t2 * self.root2) % self.p
                    transformed[i + j + 2*step] = (t0 + t1 * self.root2 + t2 * self.root1) % self.p
        return transformed % self.p

class OuroborosArchitect:
    """Authenticated Ternary Stream Cipher utilizing an NTT-backed Keystream Generator."""
    def __init__(self, key: str, block_size: int = 81) -> None:
        self.ntt = NTTEngine()
        self.block_size = block_size
        self.master_key = hashlib.pbkdf2_hmac('sha256', key.encode('utf-8'), b'dynamic_salt_context', 200000)

    def _apply_padding(self, payload: List[int]) -> List[int]:
        """Applies ISO/IEC 7816-4 equivalent ternary padding."""
        total_len = len(payload) + 1
        pad_zeros = (self.block_size - (total_len % self.block_size)) % self.block_size
        return payload + [1] + [0] * pad_zeros

    def _remove_padding(self, padded_payload: List[int]) -> List[int]:
        """Removes ternary padding safely from the back."""
        for i in range(len(padded_payload) - 1, -1, -1):
            if padded_payload[i] == 1:
                return padded_payload[:i]
        raise ValueError("Malformed padding structure detected!")

    def _generate_ks(self, nonce: bytes, length: int) -> List[int]:
        """Generates an unbiased ternary keystream using rejection sampling."""
        stream = []
        counter = 0
        while len(stream) < length:
            h = hmac.new(self.master_key, nonce + counter.to_bytes(4, 'big'), 'sha256').digest()
            raw_data = np.frombuffer(h, dtype=np.uint8)
            ntt_block = self.ntt.transform(raw_data)
            for x in ntt_block:
                if x < 17496:
                    stream.append(int(x) % 3)
                    if len(stream) == length: break
            counter += 1
        return stream

    def encrypt(self, payload: List[int]) -> Tuple[List[int], bytes, bytes]:
        """Encrypts a ternary payload providing Authenticated Encryption."""
        padded = self._apply_padding(payload)
        nonce = secrets.token_bytes(16)
        ks = self._generate_ks(nonce, len(padded))
        ciphertext = [(p + k) % 3 for p, k in zip(padded, ks)]
        tag = hmac.new(self.master_key, bytes(ciphertext) + nonce, 'sha256').digest()
        return ciphertext, nonce, tag

    def decrypt(self, ciphertext: List[int], nonce: bytes, tag: bytes) -> List[int]:
        """Decrypts and verifies ciphertext authenticity."""
        expected_tag = hmac.new(self.master_key, bytes(ciphertext) + nonce, 'sha256').digest()
        if not secrets.compare_digest(tag, expected_tag):
            raise ValueError("Integrity verification failed!")
        ks = self._generate_ks(nonce, len(ciphertext))
        decrypted = [(c - k) % 3 for c, k in zip(ciphertext, ks)]
        return self._remove_padding(decrypted)
