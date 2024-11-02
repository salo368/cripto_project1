import hashlib
import os
import numpy as np
import math
import random



def printHex(data):
    hex_string = ' '.join(data.hex()[i:i+2] for i in range(0, len(data.hex()), 2))
    print(f'Formato Hex: {hex_string}')
    bits_string = ' '.join(format(byte, '08b') for byte in data)
    print(f'Formato Bits: {bits_string}')
    print(len(data)*8)
    print()

# def generatePrivateSeed():
#     return os.urandom(32)

def generatePrivateSeed():
    random.seed(47)
    return bytes([random.getrandbits(8) for _ in range(32)])


def functionH(seed, bytes_n):
    shake = hashlib.shake_128()
    shake.update(seed)
    return shake.digest(bytes_n)

def functionG(seed, bytes_n):
    shake = hashlib.shake_128()
    shake.update(seed)
    return shake.digest(bytes_n)

def generatePublicSeedAndT(privSeed, v, m):

    byte_length = 32 + math.ceil(m / 8) * v

    output = functionH(privSeed,byte_length)

    pubSeed = output[:32] # <---------public seed
    TBytes = output[32:]

    section_size = math.ceil(m / 8)

    T_matrix = np.zeros((v, m), dtype=int)

    for i in range(v):
        section = TBytes[i * section_size:(i + 1) * section_size]
        T_matrix[i] = [(byte >> (7 - j)) & 1 for byte in section for j in range(8)][-m:]

    return pubSeed, T_matrix

def generateC_L_Q1(pubSeed, v, m):

    C_matrix = np.zeros((m, 1), dtype=int)
    L_matrix = np.zeros((m, v+m), dtype=int)
    Q1_matrix = np.zeros((m, v*m+(v*(v+1))//2), dtype=int)

    calls = math.ceil(m / 16)

    for i in range(calls):
        output = functionG(pubSeed+i.to_bytes(1, byteorder='big'),2 + 2*m +3*v + v*v + 2*m*v)

        CBytes = output[:2]
        printHex(CBytes)
        LBytes = output[2:2+2*(v+m)]
        printHex(LBytes)
        Q1Bytes = output[2+2*(v+m):]
        printHex(Q1Bytes)

        bit_string_c = ''.join(format(byte, '08b') for byte in CBytes)

        start_index = i * 16
        for j in range(16):
            if start_index + j < m:
                C_matrix[start_index + j][0] = int(bit_string_c[15 - j])

        bit_string_l = ''.join(format(byte, '08b') for byte in LBytes)
        bit_string_l = bit_string_l[::-1]

        for j in range(16):
            if start_index + j < m:
                n = v + m
                bit_group = bit_string_l[j * n:(j + 1) * n]

                for k in range(n):
                    L_matrix[start_index + j][k] = int(bit_group[k])

        bit_string_q1 = ''.join(format(byte, '08b') for byte in Q1Bytes)
        bit_string_q1 = bit_string_q1[::-1]

        for j in range(16):
            if start_index + j < m:
                n =  (v * m) + ((v * (v + 1)) // 2)
                bit_group = bit_string_q1[j * n:(j + 1) * n]

                for k in range(n):
                    Q1_matrix[start_index + j][k] = int(bit_group[k])

    
    print(C_matrix)
    print(L_matrix)
    print(Q1_matrix)

    return C_matrix, L_matrix, Q1_matrix

def findQ2(Q1, T, v, m):

    def findPk1(k, Q1, v, m):
        Pk1 = np.zeros((v, v), dtype=int)
        column = 1
        for i in range(1,v+1):
            for j in range(i, v+1):
                Pk1[i-1, j-1] = Q1[k-1, column-1]
                column += 1
            column += m
        return Pk1

    def findPk2(k, Q1, v, m):
        Pk2 = np.zeros((v, m), dtype=int)
        column = 1
        for i in range(1,v+1):
            column += v - i + 1
            for j in range(1,m+1):
                Pk2[i-1, j-1] = Q1[k-1, column-1]
                column += 1
        return Pk2

    D2 = (m *(m+1)) // 2

    Q2 = np.zeros((m, D2), dtype=int)
    for k in range(1,m+1):
        Pk1 = findPk1(k, Q1,v,m)
        Pk2 = findPk2(k, Q1,v,m)
        Pk3 = (-T.T @ Pk1 @ T + T.T @ Pk2) % 2

        column = 1
        for i in range(1,m+1):
            Q2[k-1, column-1] = Pk3[i-1, i-1]
            column += 1
            for j in range(i+1, m+1):
                Q2[k-1, column-1] = (Pk3[i-1, j-1] + Pk3[j-1, i-1]) % 2
                column += 1
    return Q2

def getPublicKey(pubSeed, Q2):

    pubSeed_bytes = bytearray(pubSeed)

    bit_sequence = []

    for col in Q2.T:
        bit_sequence.extend(col)

    bit_length = len(bit_sequence)

    if bit_length % 8 != 0:
        padding_length = 8 - (bit_length % 8)
        bit_sequence = [0] * padding_length + bit_sequence

    byte_sequence = bytearray()
    for i in range(0, len(bit_sequence), 8):
        byte = sum(bit_sequence[j] << (7 - (j % 8)) for j in range(i, i + 8))
        byte_sequence.append(byte)

    public_key = pubSeed_bytes + byte_sequence
    return public_key

def generateKeys(v,m):

    privSeed = generatePrivateSeed() # <---------private seed

    pubSeed, T = generatePublicSeedAndT(privSeed,v,m) # <--------- private seed and T matrix

    C, L, Q1 = generateC_L_Q1(pubSeed, v, m) # <--------- C matrix, L matrix and Q1 matrix

    Q2 = findQ2(Q1, T, v, m) # <--------- Q2 matrix

    privKey = privSeed # <---------private key = private seed

    pubKey = getPublicKey(pubSeed, Q2) # <---------public key

    return pubKey, privKey

def run():

    m, v = 3, 2
    # m, v = 83, 283
    # m, v = 110, 374

    public_key, private_key = generateKeys(v, m)

    # print("Public Key: ", public_key)
    # print("Private Key: ", private_key)
    # print()
    # printHex(public_key)
    # printHex(private_key)

if __name__ == "__main__":
    run()