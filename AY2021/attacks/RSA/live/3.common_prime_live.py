from Crypto.Util.number import getPrime
from math import gcd


if __name__ == '__main__':
    n_len = 2048

    p1 = getPrime(n_len)
    p2 = getPrime(n_len)
    p3 = getPrime(n_len)

    n1 = p1 * p2
    n2 = p1 * p3


    print("p1=" + str(p1))
    print("p2=" + str(p2))
    print("p3=" + str(p3))
    print("n1 =" + str(n1))
    print("n2 =" + str(n2))

    # attackers: so we only know n1 and n2 (e1=e2=65537)
    # gcd

    common_factor = gcd(n1,n2)
    print(common_factor)

    f1 = n1 // common_factor
    f2 = n2 // common_factor
