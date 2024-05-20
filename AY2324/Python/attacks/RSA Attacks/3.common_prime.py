from Crypto.Util.number import getPrime
from gmpy2 import gcd

if __name__ == '__main__':

    p1 = getPrime(1024)
    p2 = getPrime(1024)
    p3 = getPrime(1024)

    n1 = p1 * p2
    n2 = p1 * p3

    print(p1)
    print(p2)
    print(p3)


    p = gcd(n1,n2)
    print("-----------")
    print(p)
    print(n1 // p)
    print(n2 // p)
