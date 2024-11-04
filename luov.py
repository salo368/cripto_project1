import galois
from XOFs import Select_H, shake128
from math import ceil
from Crypto.Random import get_random_bytes
from typing import Tuple
import numpy as np

class LUOV():

    def __init__(self, r: int, m: int, v: int) -> None:
        self.r = r
        self.m = m
        self.v = v
        self.n = m + v
        self.h = Select_H(m, v)
        self.g = shake128
        self.field = galois.GF(2, r)

        self.c_size = 2
        self.l_size = 2 * self.n
        self.q1_size = v * (v + 1) + 2 * v * m
        self.sponge_size = self.c_size + self.l_size + self.q1_size

    def generate_private_seed(self) -> bytes:
        private_seed = get_random_bytes(32)
        with open("private_seed", "wb") as f:
            f.write(private_seed)
        return private_seed
    
    def key_generation(self, private_seed: bytes) -> Tuple[bytes, bytes]:
        private_sponge = self.initialize_and_absorb_private_seed(private_seed)
        public_seed = self.squeeze_public_seed(private_sponge)
        t = self.squeeze_t(private_sponge)
        public_sponge = self.initialize_and_absorb_public_seed(public_seed)
        c, l, q1 = self.squeeze_public_map(public_sponge)
        q2 = self.find_q2(q1, t)
        return self.encode_public_key(public_seed, q2), private_seed
    
    def bytes_to_field(self, data: bytes) -> galois.FieldArray:
        bits = []
        for byte in data:
            bits.extend(self.iter_bits(byte))
        elements = []
        for i in range(0, len(bits), self.r):
            group = bits[i:i + self.r]
            element = int("".join(str(bit) for bit in group), 2)
            elements.append(element)
        return self.field(elements)

    def hash_digest(self, message: str, salt: bytes) -> galois.FieldArray:
        digest = self.h(message.encode() + (0).to_bytes(1, 'big') + salt, self.m * self.r)
        return self.bytes_to_field(digest)

    def sign(self, private_seed: bytes, message: str):
        private_sponge = self.initialize_and_absorb_private_seed(private_seed)
        public_seed = self.squeeze_public_seed(private_sponge)
        t = self.squeeze_t(private_sponge)
        public_sponge = self.initialize_and_absorb_public_seed(public_seed)
        c, l, q1 = self.squeeze_public_map(public_sponge)
        salt = get_random_bytes(16)
        h = self.hash_digest(message, salt)
        while True:
            v = self.bytes_to_field(get_random_bytes(self.r * self.v // 8))
            a = self.build_augmented_matrix(c, l, q1, t, h, v)
            print(a)
            break
    
    def build_augmented_matrix(self, c, l, q1, t, h, v):
        v_concat_0 = self.field(np.concatenate([v, np.zeros(1)])).reshape(-1, 1)

        rhs = h.reshape(-1, 1) - c.reshape(-1, 1) - l @ v_concat_0

        lhs = l @ self.field(np.vstack([-t, np.eye(self.m)]))

        for k in range(self.m):
            pk1 = self.find_pk1(k, q1)
            pk2 = self.find_pk2(k, q1)
            rhs[k] = rhs[k] - v.T @ pk1 @ v
            fk2 = -(pk1 + pk1.T) @ t + pk2
            lhs[k] = lhs[k] + v @ fk2

        augmented_matrix = np.hstack([lhs, rhs])

        return augmented_matrix

    def initialize_and_absorb_private_seed(self, private_seed: bytes) -> bytes:
        return self.h(private_seed, 32 + ceil(self.m / 8) * self.v)

    def squeeze_public_seed(self, private_sponge: bytes) -> bytes:
        return private_sponge[-32:]
    
    def iter_bits(self, byte: int, start: int = 7) -> iter:
        return ((byte >> i) & 1 for i in range(start, -1, -1))
    
    def squeeze_t(self, private_sponge: bytes) -> galois.FieldArray:

        def t_row(first_byte_i: int) -> list[int]:
            row = []
            last_byte_i = first_byte_i + bytes_per_row - 1
            for byte_i in range(first_byte_i, last_byte_i):
                row.extend(self.iter_bits(t_bytes[byte_i]))
            row.extend(self.iter_bits(t_bytes[last_byte_i], last_byte_start))
            return row

        t_bytes = private_sponge[:-32]

        bytes_per_row = ceil(self.m / 8)
        last_byte_start = (self.m - 1) % 8

        t = [t_row(first_byte_i) for first_byte_i in range(0, len(t_bytes), bytes_per_row)]

        return self.field(t)

    def initialize_and_absorb_public_seed(self, public_seed: bytes) -> bytes:
        return b''.join(self.g(public_seed + call.to_bytes(1, 'big'), self.sponge_size) for call in range(ceil(self.m / 16)))

    def squeeze_public_map(self, public_sponge: bytes) -> Tuple[galois.FieldArray, galois.FieldArray, galois.FieldArray]:

        def transpose_column(sponge_start: int, row_i: int) -> list[int]:
            # Infex of the first byte
            start = sponge_start + 2 * row_i
            # Start the row with the least significant bits of the first pair of bytes
            row = [bit for bit in self.iter_bits(public_sponge[start] + public_sponge[start + 1], first_pair_start)]
            # From the second pair onwards append all the bits to the row
            for byte in range(start + self.sponge_size, len(public_sponge), self.sponge_size):
                row.extend(self.iter_bits(public_sponge[byte]))
                row.extend(self.iter_bits(public_sponge[byte + 1]))
            return row

        q1_start = self.c_size + self.l_size
        first_pair_start = (self.m - 1) % 16

        c = self.field([transpose_column(0, 0)]).T
        l = self.field([transpose_column(self.c_size, i) for i in range(self.l_size // 2)]).T
        q1 = self.field([transpose_column(q1_start, i) for i in range(self.q1_size // 2)]).T

        return c, l, q1

    def find_pk1(self, k: int, Q1: galois.FieldArray) -> galois.FieldArray:
        pk1 = self.field.Zeros((self.v, self.v))
        column = 0
        for i in range(self.v):
            for j in range(i, self.v):
                pk1[i, j] = Q1[k, column]
                column += 1
            column += self.m
        return pk1
    
    def find_pk2(self, k: int, Q1: galois.FieldArray) -> galois.FieldArray:
        pk2 = self.field.Zeros((self.v, self.m))
        column = 0
        for i in range(self.v):
            column += self.v - i
            for j in range(self.m):
                pk2[i, j] = Q1[k, column]
                column += 1
        return pk2

    def find_q2(self, q1: galois.FieldArray, t: galois.FieldArray) -> galois.FieldArray:
        d2 = (self.m * (self.m + 1)) // 2
        q2 = self.field.Zeros((self.m, d2))

        for k in range(self.m):
            pk1 = self.find_pk1(k, q1)
            pk2 = self.find_pk2(k, q1)
            pk3 = -t.T @ pk1 @ t + t.T @ pk2

            column = 0
            for i in range(self.m):
                q2[k, column] = pk3[i, i]
                column += 1
                for j in range(i + 1, self.m):
                    q2[k, column] = pk3[i, j] + pk3[j, i]
                    column += 1

        return q2
    
    def encode_public_key(self, public_seed: bytes, q2: galois.FieldArray):
        flat_bits = "".join(str(value) for row in q2.T for value in row)

        while len(flat_bits) % 8 != 0:
            flat_bits += '0'

        encoding = bytearray()

        for i in range(0, len(flat_bits), 8):
            byte = flat_bits[i:i + 8][::-1]
            encoding.append(int(byte, 2))

        return public_seed + bytes(encoding)
