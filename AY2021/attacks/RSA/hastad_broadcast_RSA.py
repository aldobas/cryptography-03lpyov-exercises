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


if __name__ == '__main__':


    n_length = 1024
    e = 3

    print("Starting...")

    # generate three keys with low e
    key1 = RSA.generate(n_length,e=e)
    key2 = RSA.generate(n_length,e=e)
    key3 = RSA.generate(n_length,e=e)

    n1 = key1.n
    n2 = key2.n
    n3 = key3.n

    print(n1)
    print(n2)
    print(n3)
    print(key1.e)


    # encrypt the message, no OAEP, three times
    m = b'This is a secret message'
    m_int = int.from_bytes(m,byteorder='big')
    c1 = pow(m_int,e,n1)
    c2 = pow(m_int,e,n2)
    c3 = pow(m_int,e,n3)

    # solve the Diophantine system modulo N

    g, u1, v1 = egcd(n2*n3, n1)
    g, u2, v2 = egcd(n1*n3, n2)
    g, u3, v3 = egcd(n1*n2, n3)

    c = c1 * u1 * n2*n3 + c2 * u2 * n1*n3 + c3 * u3 * n1*n2

    # c is the solution -> c = m^3 mod N, cube root will work now
    dec_int = iroot(e,c)
    print(dec_int.to_bytes(n_length,byteorder='big').decode())

