from Crypto.Util.number import getPrime

# kth root of number n
def iroot(k, n):
    u, s = n, n+1
    while u < s:
        s = u
        t = (k-1) * s + n // pow(s, k-1)
        u = t // k
    return s


n_length = 1024

p1 = getPrime(n_length)
p2 = getPrime(n_length)
n = p1 * p2

e = 17
phi = (p1-1)*(p2-1)
d = pow(e,-1,phi)

pubkey1 = (e, n)
prikey1 = (d, n)


m = b'H'
m_int = int.from_bytes(m,byteorder='big')
print(m_int)

c = pow(m_int,e,n)
print(c)
print(n)
# print(pow(c,1/e))

# dec = 310939249775

dec = iroot(e,c)

print(dec.to_bytes(n_length,byteorder='big').decode())

