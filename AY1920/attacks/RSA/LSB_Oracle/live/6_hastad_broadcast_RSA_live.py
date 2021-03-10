from Crypto.PublicKey import RSA


def iroot(k, n):
    u, s = n, n+1
    while u < s:
        s = u
        t = (k-1) * s + n // pow(s, k-1)
        u = t // k
    return s

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


n_length = 1024
e = 3

print("Starting...")

# generate the e RSA keys
key1 = RSA.generate(n_length,e=e)
key2 = RSA.generate(n_length,e=e)
key3 = RSA.generate(n_length,e=e)

n1 = key1.n
n2 = key2.n
n3 = key3.n

print(n1)
print(n2)
print(n3)

print(key2.e)

# no OAEP used
m = b'This is a long message'
m_int = int.from_bytes(m,byteorder='big')
c1 = pow(m_int,e,n1)
c2 = pow(m_int,e,n2)
c3 = pow(m_int,e,n3)

# build the new solution space

N = n1 * n2 * n3

N1 = n2 * n3
N2 = n1 * n3
N3 = n1 * n2

g, u1, v1 = egcd(N1, n1)
g, u2, v2 = egcd(N2, n2)
g, u3, v3 = egcd(N3, n3)

c = c1 * u1 * N1 + c2 * u2 * N2 +  c3 * u3 * N3

dec_int = iroot(3,c)
print(dec_int)
print(dec_int.to_bytes(n_length,byteorder='big').decode())



