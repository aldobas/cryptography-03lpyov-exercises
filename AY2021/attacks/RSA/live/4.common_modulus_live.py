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

        print("p1=" + str(p1))
        print("p2=" + str(p2))


        n = p1 * p2
        print("n=" + str(n))

        e1 = 65537
        e2 = 17

        (e,n)
        (e,n2)

        phi = (p1-1)*(p2-1)



        d1 = pow(e1, -1, n)
        d2 = pow(e2, -1, n)

        print("e1=" + str(e1))
        print("e2=" + str(e2))
        print("d1=" + str(d1))
        print("d2=" + str(d2))


    #############################################
    # generate a message and encrypt it

        plaintext = b'message'
        p_int = int.from_bytes(plaintext,byteorder='big')
        print(p_int)

        c1 = pow(p_int,e1,n)
        c2 = pow(p_int,e2,n)


        g,u,v = egcd(e1,e2)


        decrypted = pow(c1,u,n)*pow(c2,v,n) %n
        print(decrypted)
        print(decrypted.to_bytes(n_len,byteorder='big').decode())
