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
    random.seed(43)
    # return bytes([random.getrandbits(8) for _ in range(32)])
    return b' \x92\xb4Z\x0f\xad\x89\x0c\x18\xe2\x91\xe8\xbe\\xx\xb2\xd1W\x0f\xd1\x86\xf7\xe0\xc2\xcf\x1d\xc1[\xd5zZ'

def generateSalt():
    random.seed(43)
    return bytes([random.getrandbits(8) for _ in range(16)])

def generateRandomBits(n):
    return ''.join(random.choice('01') for _ in range(n))

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
        printHex(output)
        CBytes = output[:2]
        LBytes = output[2:2+2*(v+m)]
        Q1Bytes = output[2+2*(v+m):]

        bit_string_c = (''.join(format(byte, '08b') for byte in CBytes))[-(min(i*16+16,m)%16):]

        for j in range(i*16,min(i*16+16,m)):
            C_matrix[j][0] = bit_string_c[j % 16]
    
        bit_string_l = ''.join(format(byte, '08b') for byte in LBytes)
        bit_string_l_list = [bit_string_l[i:i+16] for i in range(0, len(bit_string_l), 16)]

        for k in range(v+m):
            for j in range(i*16,min(i*16+16,m)):
                L_matrix[j][k] = ((bit_string_l_list[k])[-(min(i*16+16,m)%16):])[j % 16]

        bit_string_q1 = ''.join(format(byte, '08b') for byte in Q1Bytes)
        bit_string_q1_list = [bit_string_q1[i:i+16] for i in range(0, len(bit_string_q1), 16)]

        for k in range((v*(v+1)//2) + v*m):
            for j in range(i*16,min(i*16+16,m)):
                Q1_matrix[j][k] = ((bit_string_q1_list[k])[-(min(i*16+16,m)%16):])[j % 16]

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

    privSeed = generatePrivateSeed() # <--------- private seed

    printHex(privSeed)

    pubSeed, T = generatePublicSeedAndT(privSeed,v,m) # <--------- private seed and T matrix

    print(T)

    C, L, Q1 = generateC_L_Q1(pubSeed, v, m) # <--------- C matrix, L matrix and Q1 matrix

    print(C)
    print(L)
    print(Q1)

    Q2 = findQ2(Q1, T, v, m) # <--------- Q2 matrix

    print(Q2)

    privKey = privSeed # <--------- private key = private seed

    pubKey = getPublicKey(pubSeed, Q2) # <--------- public key

    return pubKey, privKey

def sign(privKey, message, v, m, r):

    privSeed = privKey # <--------- private seed

    pubSeed, T = generatePublicSeedAndT(privSeed,v,m) # <--------- private seed and T matrix

    C, L, Q1 = generateC_L_Q1(pubSeed, v, m) # <--------- C matrix, L matrix and Q1 matrix

    salt = generateSalt() # <--------- salt

    h = functionH(message + b'\x00' + salt, m*r) # <--------- h

    vinager = generateRandomBits(10) # <--------- vinager variables

    

def run():

    r, v, m = 1, 5, 4 

    public_key, private_key = generateKeys(v, m)

    sign(private_key, "Hola mundo".encode(), v, m, r)

if __name__ == "__main__":
    run()