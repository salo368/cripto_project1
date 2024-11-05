
from XOFs import selectedXOF, shake128
from Crypto.Random import get_random_bytes
from typing import Tuple
from math import ceil
import galois
import numpy as np

class LUOV():

    def __init__(self, r: int, m: int, v: int) -> None:
        self.r = r
        self.m = m
        self.v = v
        self.n = m + v
        self.functionH = selectedXOF(m, v)
        self.functionG = shake128

        self.privateKey = None
    
    def generatePrivateSeed(self) -> bytes:
        privateSeed = get_random_bytes(32)
        privateSeed = b' \x92\xb4Z\x0f\xad\x89\x0c\x18\xe2\x91\xe8\xbe\\xx\xb2\xd1W\x0f\xd1\x86\xf7\xe0\xc2\xcf\x1d\xc1[\xd5zZ'
        return privateSeed
    
    def keyGeneration(self, privateSeed: bytes) -> Tuple[bytes, bytes]:

        privateSponge = self.initializeAndAbsorbPrivateSeed(privateSeed)
      
        publicSeed = self.squeezePublicSeed(privateSponge)
 
        T = self.squeezeT(privateSponge)

        publicSponge = self.initializeAndAbsorbPublicSeed(publicSeed)

        C, L, Q1 = self.squeezePublicMap(publicSponge)

        Q2 = self.findQ2(Q1, T)

        publicKey = self.encodePublicKey(publicSeed, Q2)

        return publicKey, privateSeed
        

    def initializeAndAbsorbPrivateSeed(self, privateSeed: bytes) -> bytes:
        return self.functionH(privateSeed, 32 + ceil(self.m / 8) * self.v)

    def squeezePublicSeed(self, privateSponge: bytes) -> bytes:
        return privateSponge[:32]
    
    def squeezeT(self, privateSponge: bytes) -> galois.GF:
        
        TBytes = privateSponge[32:]
        GF = galois.GF(2)
        T = GF.Zeros((self.v, self.m))

        sectionSize = ceil(self.m / 8)

        for i in range(self.v):
            row = TBytes[i * sectionSize:(i + 1) * sectionSize]
            bits = [(byte >> (7 - j)) & 1 for byte in row for j in range(8)][-self.m:] 
            for j in range(len(bits)): 
                T[i, j] = GF(bits[j])

        return T

    def initializeAndAbsorbPublicSeed(self, publicSeed: bytes) -> bytes:

        calls = ceil(self.m / 16)
        size = 2 + 2 * self.m + 3 * self.v + self.v * self.v + 2 * self.m * self.v  
        callsHash = b'' 
        for i in range(calls):
            callsHash += self.functionG(publicSeed + i.to_bytes(1, byteorder='big'), size)

        return callsHash
    
    def squeezePublicMap(self, publicSponge: bytes) -> Tuple[galois.GF, galois.GF, galois.GF]: 

        calls = ceil(self.m / 16)
        blockSize = len(publicSponge) // calls

        callsBlocks = [publicSponge[i * blockSize:(i + 1) * blockSize] for i in range(calls)]

        GF = galois.GF(2)
        C = GF.Zeros((self.m, 1))
        L = GF.Zeros((self.m, self.v + self.m))
        Q1 = GF.Zeros((self.m, self.v*self.m+(self.v*(self.v+1))//2))
        
        for i, block in enumerate(callsBlocks):
            CBytes = block[:2]
            LBytes = block[2:2+2*(self.v + self.m)]
            Q1Bytes = block[2+2*(self.v + self.m):]
        
            bitsC = (''.join(format(byte, '08b') for byte in CBytes))[-(min(i*16+16,self.m)%16):]

            for j in range(i*16,min(i*16+16,self.m)):
                C[j, 0] = GF(bitsC[j % 16])

            bitsL = ''.join(format(byte, '08b') for byte in LBytes)
            bitsLColumns = [bitsL[i:i+16] for i in range(0, len(bitsL), 16)]

            for k in range(self.v+self.m):
                for j in range(i*16,min(i*16+16,self.m)):
                    L[j, k] = GF(((bitsLColumns[k])[-(min(i*16+16,self.m)%16):])[j % 16])

            bitsQ1 = ''.join(format(byte, '08b') for byte in Q1Bytes)
            bitsQ1Columns = [bitsQ1[i:i+16] for i in range(0, len(bitsQ1), 16)]

            for k in range((self.v*(self.v+1)//2) + self.v*self.m):
                for j in range(i*16,min(i*16+16,self.m)):
                    Q1[j][k] = ((bitsQ1Columns[k])[-(min(i*16+16,self.m)%16):])[j % 16]
        
        return C, L, Q1
            
    def findQ2(self, Q1: galois.GF, T: galois.GF) -> galois.GF:

        GF = galois.GF(2)

        def findPk1(k, Q1):
            Pk1 = GF.Zeros((self.v, self.v))
            column = 1
            for i in range(1,self.v+1):
                for j in range(i, self.v+1):
                    Pk1[i-1, j-1] = Q1[k-1, column-1]
                    column += 1
                column += self.m
            return Pk1

        def findPk2(k, Q1):
            Pk2 = GF.Zeros((self.v, self.m))
            column = 1
            for i in range(1,self.v+1):
                column += self.v - i + 1
                for j in range(1,self.m+1):
                    Pk2[i-1, j-1] = Q1[k-1, column-1]
                    column += 1
            return Pk2

        D2 = (self.m *(self.m+1)) // 2
        Q2 = GF.Zeros((self.m, D2))

        for k in range(1, self.m+1):
            Pk1 = findPk1(k, Q1)
            Pk2 = findPk2(k, Q1)
            Pk3 = T.T @ Pk2 - T.T @ Pk1 @ T

            column = 1
            for i in range(1, self.m+1):
                Q2[k-1, column-1] = Pk3[i-1, i-1]
                column += 1
                for j in range(i+1, self.m+1):
                    Q2[k-1, column-1] = (Pk3[i-1, j-1] + Pk3[j-1, i-1])
                    column += 1

        return Q2
    
    def encodePublicKey(self, publicSeed: bytes, Q2: galois.GF) -> bytes:

        bits = ""
        for col in range((self.m *(self.m+1)) // 2):
            for row in range(self.m):
                bits += str(Q2[row, col])
        
        padding = 8 - (len(bits) % 8)
        if padding != 8:  
            bits += '0' * padding

        encodedQ2 = bytes.fromhex(hex(int(bits, 2))[2:].zfill((len(bits) + 3) // 4))

        return publicSeed + encodedQ2
    
    def generateSalt(self) -> bytes:
        salt = get_random_bytes(16)
        # salt = b'\xa1w\x7f;\\\xef=7\xb0C\x8c\xfa\x16H:|'
        return salt
    
    def generateVinager(self) -> bytes:
        vinager = get_random_bytes(ceil(self.r * self.v /8))
        # vinager = b'\x1e\x9c'
        return vinager
    
    def vinagerToMatrix(self, vinager: bytes) -> galois.GF:
        GF = galois.GF(2**self.r)
        V = GF.Zeros((self.v, 1))

        bits = ''.join(f"{byte:08b}" for byte in vinager)

        for i in range(0, self.v):
            block = bits[i * self.r: (i+1) * self.r]
            value = int(block, 2)
            V[i, 0] = GF(value)
    
        return V
    
    def hToMatrix(self, vinager: bytes) -> galois.GF:
        GF = galois.GF(2**self.r)
        H = GF.Zeros((self.m, 1))

        bits = ''.join(f"{byte:08b}" for byte in vinager)

        for i in range(0, self.m):
            block = bits[i * self.r: (i+1) * self.r]
            value = int(block, 2)
            H[i, 0] = GF(value)

        return H

    def buildAugmentedMatrix(self, C: galois.GF, L: galois.GF, Q1: galois.GF, T: galois.GF, h: bytes, vinager: bytes) -> galois.GF:

        GF = galois.GF(2**self.r)

        def findPk1(k, Q1):
            Pk1 = GF.Zeros((self.v, self.v))
            column = 1
            for i in range(1,self.v+1):
                for j in range(i, self.v+1):
                    Pk1[i-1, j-1] = Q1[k-1, column-1]
                    column += 1
                column += self.m
            return Pk1

        def findPk2(k, Q1):
            Pk2 = GF.Zeros((self.v, self.m))
            column = 1
            for i in range(1,self.v+1):
                column += self.v - i + 1
                for j in range(1,self.m+1):
                    Pk2[i-1, j-1] = Q1[k-1, column-1]
                    column += 1
            return Pk2

        V = self.vinagerToMatrix(vinager)
        H = self.hToMatrix(h)
        C = GF(C)
        L = GF(L)
        Q1 = GF(Q1)
        T = GF(T)

        RHS = H - C - (L @ np.vstack((V, GF.Zeros((self.m, 1))))) 

        LHS = L @ np.vstack((-T, GF.Ones((self.m, self.m))))

        for k in range(1, self.m+1):
            Pk1 = findPk1(k, Q1)
            Pk2 = findPk2(k, Q1)

            RHS[k-1] = RHS[k-1] - V.T @ Pk1 @ V

            Fk2 = -(Pk1 + Pk1.T) @ T + Pk2

            LHS[k-1] = LHS[k-1] + V.T @ Fk2
        
        A = np.hstack((LHS, RHS))
        return A

    def gaussianElimination(self, M: galois.GF)-> galois.GF:

        GF = galois.GF(2**self.r)
        A = M[:, :-1]   
        b = M[:, -1] 
        
        X = np.linalg.solve(A, b)

        return GF([X])
    
    def encodeSignature(self, S: galois.GF, salt: bytes) -> bytes:

        bits = ""
        for i in range(self.m + self.v): 
            value = format(S[i,0], f'0{self.r}b')
            bits += value
        
        padding = 8 - (len(bits) % 8)
        if padding != 8:  
            bits += '0' * padding

        encodedS = bytes.fromhex(hex(int(bits, 2))[2:].zfill((len(bits) + 3) // 4))

        return encodedS+salt

    def sign(self, privateSeed: bytes, message: bytes) -> bytes:
        
        privateSponge = self.initializeAndAbsorbPrivateSeed(privateSeed)
      
        publicSeed = self.squeezePublicSeed(privateSponge)
 
        T = self.squeezeT(privateSponge)

        publicSponge = self.initializeAndAbsorbPublicSeed(publicSeed)

        C, L, Q1 = self.squeezePublicMap(publicSponge)

        while True:

            salt = self.generateSalt()

            h = self.functionH(message + b'\x00' + salt, ceil(self.m * self.r / 8))

            vinager = self.generateVinager()

            A = self.buildAugmentedMatrix(C, L, Q1, T, h, vinager)

            try:
                O = self.gaussianElimination(A)
                V = self.vinagerToMatrix(vinager).T
                S_prime = np.hstack((V,O)).T
                break 
            except Exception as e:
                print("No unique solution for h")
                continue 
        
        GF = galois.GF(2**self.r)

        S = np.hstack((np.vstack((GF.Ones((self.v, self.v)), GF.Zeros((self.m, self.v)))),np.vstack((-GF(T), GF.Ones((self.m, self.m)))))) @ S_prime
        
        signature = self.encodeSignature(S, salt)

        return signature
   
def printHex(data):
    hex_string = ' '.join(data.hex()[i:i+2] for i in range(0, len(data.hex()), 2))
    print(f'Formato Hex: {hex_string}')
    bits_string = ' '.join(format(byte, '08b') for byte in data)
    print(f'Formato Bits: {bits_string}')
    print(len(data)*8)
    print()

# luov = LUOV(7, 57, 197)
luov = LUOV(3, 4, 5)
privateSeed = luov.generatePrivateSeed()
# luov.keyGeneration(privateSeed)
message = "Hola Mundo"
signature = luov.sign(privateSeed, message.encode())
printHex(signature)
