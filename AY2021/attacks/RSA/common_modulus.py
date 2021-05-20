from Crypto.Util.number import getPrime




def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

if __name__ == '__main__':

    n_length = 1024 #bit

    p1 = getPrime(n_length)
    p2 = getPrime(n_length)
    print(p1)
    print(p2)

    n = p1 * p2
    print(n)
    # print(n2)

    e1 = 65537 # f4

    phi = (p1-1)*(p2-1)
    print(phi)

    d1 = pow(e1, -1, phi)
    print(d1)

    pubkey1 = (e1,n)
    prikey1 = (d1,n)


    ############################
    e2 = 17 # f1

    d2 = pow(e2, -1, phi)
    print(d2)

    pubkey2 = (e2,n)
    prikey2 = (d2,n)

    #############################
    plaintext = b'AAAAAAA'
    plaintext_int = int.from_bytes(plaintext,byteorder='big')
    c1 = pow(plaintext_int,e1,n)
    c2 = pow(plaintext_int,e2,n)

    res = egcd(e1,e2)
    u = res[1]
    v = res[2]

    val = u*e1 + v*e2
    print(val)

    decrypted = pow(c1,u,n)*pow(c2,v,n) % n
    print(decrypted)
    print(decrypted.to_bytes(n_length,byteorder='big').decode())

