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

    k1 = RSA.generate(n_length,e=e)
    k2 = RSA.generate(n_length,e=e)
    k3 = RSA.generate(n_length,e=e)

    n1 = k1.n
    n2 = k2.n
    n3 = k3.n



    message = b'This is a secret msg!'
    m_int = int.from_bytes(message,byteorder='big')

    # encrypt the message, no OAEP, three times
    c1 = pow(m_int, e, n1)
    c2 = pow(m_int, e, n2)
    c3 = pow(m_int, e, n3)

    # after sniffing messages I have exactly e encrypted message


    # build a larger field n = n1*n2*n3
    # construct c = m^e mod n
    # solve the Diophantine system modulo N

    g, u1, v1 = egcd(n2*n3, n1)
    g, u2, v2 = egcd(n1 * n3, n2)
    g, u3, v3 = egcd(n1 * n2, n3)

    c = c1 * u1 *n2*n3 + c2*u2*n1*n3 + c3*u3*n1*n2

    dec_int = iroot(e,c)

    # print results
    print(dec_int.to_bytes(n_length,byteorder='big').decode())
