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
print(n)

#euler function
phi = (p1-1)*(p2-1)

#public parameter
e = 65537

#compute the private parameter
d= pow(e,-1,phi)

print(d)

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
print(C)

#decryption with private key
D = pow(C,d,n)
print(D)

#interpret as a text string again
msg = D.to_bytes(n_length,byteorder='big')
print(msg)
print(msg.decode())
