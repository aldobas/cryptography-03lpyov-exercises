from Crypto.Util.number import getPrime

#kth root of the number n
def iroot(k, n):
    u, s = n, n+1
    while u < s:
        s = u
        t = (k-1) * s + n // pow(s, k-1)
        u = t // k
    return s


n_length = 400

p1 = getPrime(n_length)
p2 = getPrime(n_length)
print(p1)
print(p2)

n = p1 * p2
print(n)

e = 17
phi = (p1-1)*(p2-1)
print(phi)

d = pow(e, -1, phi)
print(d)

pubkey1 = (e,n)
prikey1 = (d,n)


m = b'AAAA'
m_int = int.from_bytes(m,byteorder='big')
print(m_int)
# print(m_int.to_bytes(n_length,byteorder='big').decode())

c = pow(m_int,e,n)
print(c)

dec = pow(c,1/e)
print(dec)
#dec_int = 65

d_int = iroot(e,c)

print(d_int)
print(d_int.to_bytes(n_length,byteorder='big').decode())

