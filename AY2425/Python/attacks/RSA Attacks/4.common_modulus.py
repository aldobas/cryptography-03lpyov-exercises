from Crypto.Util.number import getPrime


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)



if __name__ == '__main__':
    n_len = 1024

    p1 = getPrime(n_len)
    p2 = getPrime(n_len)
    n= p1*p2
    print("p1 =" + str(p1))
    print("p2 =" + str(p2))
    print("n  =" + str(n))

    e1 = 65537
    e2 = 17

    phi = (p1-1)*(p2-1)
    res = egcd(e1, phi)
    if res[0] != 1:
        raise ValueError
    res = egcd(e2, phi)
    if res[0] != 1:
        raise ValueError

    d1 = pow(e1,-1,phi)
    d2 = pow(e2, -1, phi)

    rsa1_pub = (e1,n)
    rsa1_pri = (d1, n)

    rsa2_pub = (e2,n)
    rsa2_pri = (d2, n)


    #######################33
    plaintext = b'this is a byte string'
    plaintext_int = int.from_bytes(plaintext,byteorder='big')
    print(plaintext_int)

    c1 = pow(plaintext_int,e1,n)
    c2 = pow(plaintext_int, e2, n)

    res = egcd(e1,e2)
    u = res[1]
    v = res[2]

    val = u*e1 + v * e2
    print(val)

    decrypted = pow(c1,u,n) * pow(c2,v,n) % n
    print(decrypted)
    print(decrypted.to_bytes(decrypted.bit_length()//8 + 1, byteorder='big').decode())

