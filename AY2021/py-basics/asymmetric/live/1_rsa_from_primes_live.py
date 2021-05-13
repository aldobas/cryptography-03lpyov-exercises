from Crypto.Util.number import getPrime
from math import gcd

N = 1024
# generate primes,n,phi
p1 = getPrime(N)
p2 = getPrime(N)
print("p1 = " + str(p1))
print("p2 = " + str(p2))

n = p1 * p2 #2*1024
phi = (p1-1) * (p2 -1)
print("n = " + str(n))
print("phi= " + str(phi))


# generate public and private parameters
e = 65537
# CHECK gcd(e,phi) != 1
if gcd(e,phi) != 1:
    raise ValueError
    exit(1)
print("e = " + str(e))

# e * d = 1 mod phi
d = pow(e, -1, phi)
print("d = " + str(d))

public_key = (e,n)
private_key = (d,n)


# encrypt a message: Alice
message = b'this is a secret message to encrypt'
int_message = int.from_bytes(message, byteorder='big')
print(int_message)

if int_message >= n:
    raise ValueError
    exit(1)

enc = pow(int_message,e,n)
print("enc="+str(enc))


#decrypt a message: BOB
dec = pow(enc,d,n)
print("dec="+str(dec))
print(dec.to_bytes(2*N,byteorder='big').decode())
