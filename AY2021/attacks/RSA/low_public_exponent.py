from Crypto.Util.number import getPrime
from math import gcd

#kth root of the number n
def iroot(k, n):
    u, s = n, n+1
    while u < s:
        s = u
        t = (k-1) * s + n // pow(s, k-1)
        u = t // k
    return s

if __name__ == '__main__':


    n_length = 400

    p1 = getPrime(n_length)
    p2 = getPrime(n_length)
    print(p1)
    print(p2)

    n = p1 * p2
    print(n)

    e = 3
    phi = (p1-1)*(p2-1)
    print(phi)

    if gcd(e, phi) != 1:
        raise ValueError

    d = pow(e, -1, phi)
    print(d)

    pubkey1 = (e,n)
    prikey1 = (d,n)


    m = b'AAAA'
    m_int = int.from_bytes(m,byteorder='big')
    print(m_int)

    c = pow(m_int,e,n)
    print(c)

    d_int = iroot(e,c)
    print(d_int)
    print(d_int.to_bytes(n_length,byteorder='big').decode())

    dec = pow(c,1/e)
    print(dec)




