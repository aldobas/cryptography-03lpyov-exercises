from Crypto.PublicKey import RSA


#kth root of the number n
def iroot(k, n):
    u, s = n, n+1
    while u < s:
        s = u
        t = (k-1) * s + n // pow(s, k-1)
        u = t // k
    return s

if __name__ == '__main__':

    rsa_keypair = RSA.generate(2048, e = 3)
    e = rsa_keypair.e
    # d = rsa_keypair.d
    n = rsa_keypair.n

    m = b'This message needs to be encryptedcccccccccccccccccccccccccccccccddddddddddddddddddddddddddddddddddddddddddddddddddddd'
    m_int = int.from_bytes(m,byteorder='big')

    c = pow(m_int,e,n)

    decrypted_int = iroot(e, c)
    print(decrypted_int)
    print(decrypted_int.to_bytes(decrypted_int.bit_length() // 8 +1, byteorder='big').decode())

    dec = pow(c, 1/3)
    print(dec)
