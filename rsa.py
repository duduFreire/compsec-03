from random import randint
from math import gcd
import hashlib
from dataclasses import dataclass

from typing import Callable

HashFunc = Callable[[int], int]

@dataclass(frozen=True)
class Key:
    mod: int
    key: int

def read_key(key_path: str) -> Key:
    with open(key_path, "r") as f:
        mod_str, key_str  = f.read().split()
        return Key(mod=int(mod_str), key=int(key_str))

def binary_exp(a : int, b : int, n : int) -> int:
    """
    Computes a^b % n
    """
    a = a % n
    result = 1
    while b > 0:
        if b % 2 == 1:
            result = (result * a) % n

        b //= 2
        a = (a * a) % n
    
    return result

def extended_euclid(a : int, b : int) -> tuple[int, int, int]:
    """
    Let d = gcd(a, b). Returns (d, x, y) with
    a * x + b * y = d
    """
    oldr, r = a, b
    olds, s = 1, 0
    oldt, t = 0, 1

    while r != 0:
        q = oldr // r
        oldr, r = r, oldr - q * r
        olds, s = s, olds - q * s
        oldt, t = t, oldt - q * t
    
    return (oldr, olds, oldt)

def mul_inv(a : int, n : int) -> int:
    """
    Finds 1/a % n
    """
    (d, inv, k) = extended_euclid(a, n)
    return inv % n


def check_composite(a : int, n : int, s : int, d : int) -> bool:
    """
    Finds if a number is composite givem some base
    """
    cur = binary_exp(a, d, n)
    if cur == n-1 or cur == 1: return False
    for r in range(1, s):
        cur = (cur * cur) % n
        if cur == n-1: return False
    
    return True

def is_prime(n : int, iterations : int = 5) -> bool:
    """
    Check if n is prime using miller rabin
    """
    if n <= 4: return n == 2 or n == 3

    # n-1 = 2^s *  d
    s = 0   
    d = n-1
    while d % 2 == 0:
        d //= 2
        s += 1
    
    for i in range(iterations):
        a = randint(2, n-2)
        if check_composite(a, n, s, d): return False
    
    return True

def random_prime(prime_size: int = 1024) -> int:
    """
    Generate a random prime between (2^(prime_size/2) and (2^prime_size)
    """
    lower_bound = prime_size//2
    p = randint(1 << lower_bound, (1 << prime_size) - 1)
    if p % 2 == 0: p += 1
    while True:
        if is_prime(p): return p
        p += 2
        if p >= (1 << prime_size):
            p = (1 << lower_bound) + 1

def create_key(key_size: int  = 2048) -> tuple[Key, Key]:
    """
    Generate a RSA public key and a private key
    """
    p = random_prime(key_size // 2)
    q = random_prime(key_size // 2)
    mod = p*q
    phi_mod = (p-1) * (q-1)

    public_key = randint(2, mod-1)
    if public_key % 2 == 0: 
        public_key += 1

    while gcd(public_key, phi_mod) != 1:
        public_key += 2
        if public_key >= phi_mod: 
            public_key = 3
    
    private_key = mul_inv(public_key, phi_mod)
    return Key(mod=mod, key=public_key), Key(mod=mod, key=private_key)
    

def encrypt(msg : int, public_key: Key) -> int:
    """
    Encrypts a message using some key
    """
    return binary_exp(msg, public_key.key, public_key.mod)

def decrypt(cypher : int, private_key: Key) -> int:
    """
    Decrypts a message using some key
    """
    return binary_exp(cypher, private_key.key, private_key.mod)

def hashf_sha3_256(x: int) -> int:
    """
    sha3_256 hash function for integer
    """
    h = hashlib.sha3_256(x.to_bytes(2048, "little"))
    return int.from_bytes(h.digest(), "little")

def sign(
    msg : int, private_key: Key,
    hashf : HashFunc = hashf_sha3_256
) -> int:
    """
    Generate a signature givem a key
    """
    return encrypt(hashf(msg), private_key)


def encrypt_and_sign(
    msg : int, 
    sender_private_key: Key, receiver_public_key: Key, 
    hashf : HashFunc = hashf_sha3_256
) -> tuple[int, int]:
    """
    Encrypts a message and generate a signature
    """
    cypher = encrypt(msg, receiver_public_key)
    signature = sign(msg, sender_private_key, hashf)
    return (cypher, signature)

def decrypt_message_and_verify(
    cypher : int, signature : int,
    receiver_private_key: Key, sender_public_key: Key,
    hashf: HashFunc = hashf_sha3_256,
) -> tuple[bool, int]:
    """
    Decrypts a message and check signature
    """
    msg = decrypt(cypher, receiver_private_key)
    hash_msg = hashf(msg)
    decrypt_signature = decrypt(signature, sender_public_key)
    return (decrypt_signature == hash_msg), msg


if __name__ == "__main__":
    sender_public_key, sender_private_key, = create_key()
    receiver_public_key, receiver_private_key, = create_key()
    msg = 123456789
    cypher, signature = encrypt_and_sign(msg, sender_private_key, receiver_public_key)
    print(decrypt_message_and_verify(cypher, signature, receiver_private_key, sender_public_key))
