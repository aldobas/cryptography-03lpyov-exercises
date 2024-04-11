from Crypto.Util import number

#implement trivial RSA
n_length = 1024

#generate the primes
p1 = number.getPrime(n_length)
print(p1)

p2 = number.getPrime(n_length)
print(p2)

#modulus
n = p1 * p2
print("n="+str(n))

#euler function
phi = (p1-1)*(p2-1)

#public parameter
# e = 65537 # few bytes to 1 in the binary representation
e=65537

#GCD(e,phi) == 1?
from math import gcd
g = gcd(e,phi)
print(g)
if g != 1 :
    raise ValueError


#compute the private parameter
# e * d = 1 + k phi(n)
d= pow(e,-1,phi)

print("d="+str(d))

#just check that everything is OK
print(e*d%phi)

#create the public and private keys as Python pairs
public = (e,n)
private = (d,n)

#just print the private exponent
print(public[0])

#trivial encryption of a message


m = b'this is the message to encrypt'

#integer representation of the message to encrypt (raise to)
m_int = int.from_bytes(m,byteorder='big')
print(m_int)

# message bounded to the modulus
if m_int > n:
    raise ValueError

#encryption with public key
C = pow(m_int,e,n)
print("c="+str(C))

#decryption with private key
D = pow(C,d,n)
print(D)

#interpret as a text string again
msg = D.to_bytes(n_length,byteorder='big')
print(msg)
print(msg.decode())
