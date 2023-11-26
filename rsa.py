from random import randint
from math import gcd
import hashlib

HashFunc = any

def binary_exp(a : int, b : int, n : int) -> int:
	a = a % n
	result = 1
	while b > 0:
		if b % 2 == 1:
			result = (result * a) % n

		b //= 2
		a = (a * a) % n
	
	return result


# Let d = gcd(a, b). Returns (d, x, y) with
# a * x + b * y = d
def extended_euclid(a : int, b : int) -> (int, int, int):
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
	(d, inv, k) = extended_euclid(a, n)
	return inv % n


def check_composite(a : int, n : int, s : int, d : int) -> bool:
	cur = binary_exp(a, d, n)
	if cur == n-1 or cur == 1: return False
	for r in range(1, s):
		cur = (cur * cur) % n
		if cur == n-1: return False
	
	return True

def is_prime(n : int, iterations : int = 5) -> bool:
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

def random_prime() -> int:
	while True:
		p = randint(1 << 1000, (1 << 1024)-1)
		if is_prime(p): return p

def random_prime2() -> int:
	p = randint(1 << 1000, (1 << 1024) - 1)
	if p % 2 == 0: p += 1
	while True:
		if is_prime(p): return p
		p += 2
		if p >= (1 << 1024):
			p = (1 << 1000) + 1

def create_key() -> (int, int, int):
	p = random_prime2()
	q = random_prime2()
	n = p*q
	phi_n = (p-1) * (q-1)
	# e coprime to phi(n)
	e = randint(2, n-1)
	if e % 2 == 0: e += 1
	while True:
		if gcd(e, phi_n) == 1: break
		e += 2
		if e >= n: e = 3
	
	d = mul_inv(e, phi_n)
	return (n, e, d)
	

# Encrypts message m with public key (n, e)
# TODO: add type for public key
def encrypt(msg : int, n : int, e : int) -> int:
	return binary_exp(msg, e, n)

def decrypt(cypher : int, n : int, d : int) -> int:
	return binary_exp(cypher, d, n)

def sign(msg : int, d : int, n : int,
  hashf : HashFunc) -> int:
	return binary_exp(hashf(msg), d, n)

def encrypt_and_sign(msg : int, na : int, da : int, 
	eb : int, nb : int, hashf : HashFunc) -> (int, int):
	cypher = encrypt(msg, nb, eb)
	hasha = hashf(msg)
	signature = binary_exp(hasha, da, na)
	return (cypher, signature)


def verify_message(cypher : int, signature : int,
  hashf : HashFunc, ea : int, 
  db : int, na : int, nb : int) -> (bool, int):

	msg = decrypt(cypher, nb, db)
	hashb = hashf(msg)
	hasha = binary_exp(signature, ea, na)
	return hasha == hashb, msg

def iden(x):
	h = hashlib.sha3_256(x.to_bytes(1024, "little"))
	return int.from_bytes(h.digest(), "little")


(na, ea, da) = create_key()
(nb, eb, db) = create_key()
m = 123456789
c, s = encrypt_and_sign(m, na,da,eb,nb, iden)
print(verify_message(c,s,iden, ea,db,na,nb))
