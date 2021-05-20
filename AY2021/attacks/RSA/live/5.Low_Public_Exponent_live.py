from Crypto.Util.number import getPrime
from math import gcd


# compute the kth root of n
def iroot(k, n):
    u, s = n, n+1
    while u < s:
        s = u
        t = (k-1) * s + n // pow(s, k-1)
        u = t // k
    return s


if __name__ == '__main__':
    n_len = 512

    p1 = getPrime(n_len)
    p2 = getPrime(n_len)

    print("p1=" + str(p1))
    print("p2=" + str(p2))

    n = p1 * p2
    print("n=" + str(n))

    e = 3

    phi = (p1-1)*(p2-1)

    if gcd(e,phi) != 1:
        raise ValueError

    d = pow(e,-1,phi)
    print("d=" + str(d))

    # generate a message and encrpt it
    plaintext = b"message"
    p_int = int.from_bytes(plaintext,byteorder='big')
    print(p_int)

    c = pow(p_int,e,n)

    #e-th root
    dec = iroot(e,c)
    print(dec)
    print(dec.to_bytes(n_len,byteorder='big').decode())

    dec2 = pow(c,1/3)
    print(dec2)





    # decipher using cubic root

