import hashlib, os

from typing import Callable

HashF = Callable[[bytes], bytes]
MgfFunc = Callable[[bytes, int, HashF], bytes]

def xor(a: bytes, b: bytes) -> bytes:
    return bytes(a^b for a, b in zip(a, b))

def hashf_sha3_256(m: bytes) -> bytes:
    sha3 = hashlib.sha3_256()
    sha3.update(m)
    return sha3.digest()

def mgf1(seed: bytes, length: int, hash_func=hashlib.sha1) -> bytes:
    """Mask generation function."""
    hLen = hash_func().digest_size

    if length > (hLen << 32):
        raise ValueError("mask too long")

    T = b""
    counter = 0
    while len(T) < length:
        C = int.to_bytes(counter, 4, "big")
        T += hash_func(seed + C).digest()
        counter += 1

    return T[:length]

def encode(
    msg: bytes, sz: int, label: bytes = b"", 
    mgf: MgfFunc = mgf1, hashf: HashF = hashf_sha3_256
) -> bytes:
    lhash = hashf(label)
    hlen = len(lhash)
    msglen = len(msg)
    ps = b"\x00" * (sz - msglen - 2*hlen - 2)
    db = lhash + ps + b"\x01" + msg

    seed = os.urandom(hlen)
    db_mask = mgf(seed, sz-hlen-1)
    masked_db = xor(db, db_mask)

    seed_mask = mgf(masked_db, hlen)
    masked_seed = xor(seed, seed_mask)

    encode_msg = b"\x00" + masked_seed + masked_db
    return encode_msg

def decode(
    cypher: bytes, sz: int, label: bytes = b"", 
    mgf: MgfFunc = mgf1, hashf: HashF = hashf_sha3_256
) -> bytes:
    lhash = hashf(label)
    hlen = len(lhash)
    masked_seed, masked_db = cypher[1:1 + hlen], cypher[1+hlen:]

    seed_mask = mgf(masked_db, hlen)
    seed = xor(masked_seed, seed_mask)

    db_mask = mgf(seed, sz - hlen - 1)
    db = xor(masked_db, db_mask)
    i = hlen

    while i < len(db):
        if db[i] == 1:
            i +=1
            break
        i+=1
    msg = db[i:]
    return msg

if __name__ == "__main__":
    cypher = encode(b"abcdef", 2048)
    print(str(decode(cypher, 2048), "utf-8"))
