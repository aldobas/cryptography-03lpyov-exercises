from gmpy2 import isqrt
from Crypto.Util.number import getPrime
from sympy import nextprime

# p = a+ b, q = a-b
# n = a**2 - b**2
# a**2 - n = s = b**2 --> isqrt(x) is b
def fermat(n):
    print("init")
    a = b = isqrt(n)
    x = pow(a,2) - n

    print("a = "+str(a))
    print("b = " + str(b))

    print("cycle")

    while True:
        if x == pow(b,2):
            print("found")
            break;
        else:
            a +=1
            x = pow(a, 2) - n
            b = isqrt(x)
            print("a = " + str(a))
            print("b = " + str(b))
            print("delta = " + str(n - pow(a,2) + pow(b,2)))

    p = a + b
    q = a - b

    return p, q


if __name__ == '__main__':
    n_length = 100
    p1 = getPrime(n_length)

    delta = 1000000000000000000

    p2 = nextprime(p1+delta)


    n = p1 * p2
    print(p1)
    print(p2)
    print(n)

    q1,q2 = fermat(n)
    print(q1)
    print(q2)
