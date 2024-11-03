from Crypto.Hash import SHAKE128
from Crypto.Hash import SHAKE256

from typing import Callable

def shake128(data: bytes, length: int) -> bytes:
    shake = SHAKE128.new()
    shake.update(data)
    return shake.read(length)

def shake256(data: bytes, length: int) -> bytes:
    shake = SHAKE256.new()
    shake.update(data)
    return shake.read(length)

def  Select_H(m: int, v: int) -> Callable[[bytes, int], bytes]:
    if m == 57 and v == 197:
        return shake128
    if m == 42 and v == 182:
        return shake128
    return shake256
