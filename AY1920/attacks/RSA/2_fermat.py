from gmpy2 import isqrt
from Crypto.Util.number import getPrime
from sympy import nextprime
# from egcd import egcd

# def fermat(n):
#
#     print("init")
#     a = b = isqrt(n)
#     b2 = a * a - n
#     print("a = " + str(a))
#     print("b = " + str(b))
#     print("b2= " + str(b2))
#
#     print("cycle")
#
#     while pow(b,2) != b2:
#         a = a + 1
#         b2 = pow(a,2) - n
#         b = isqrt(b2)
#         print("a = " + str(a))
#         print("b = " + str(b))
#         print("b2= " + str(b2))
#
#     print("found")
#     p = a+b
#     q = a-b
#     assert n == p * q
#     return p, q


def fermat(n):
    print("init")
    a = isqrt(n)
    b = isqrt(n)
    x = pow(a, 2) - n

    print("a = " + str(a))
    print("b = " + str(b))
    # print("x = " + str(x))

    print("cycle")
    while True:
        if x == pow(b, 2):
            print("found")
            break;
        else:
            a += 1
            x = pow(a,2) - n
            b = isqrt(x)
        print("a = " + str(a))
        print("b = " + str(b))
        # print("x = " + str(x))
        print("delta = " + str(n - pow(a,2) + pow(b,2)))

    p = a + b
    q = a - b
    # assert n == p * q
    return p, q


if __name__ == '__main__':

    delta = 10000000

    p1 = getPrime(40)
    print(p1)

    p2 = nextprime(p1+delta)
    print(p2)

    n = p1*p2
    print(n)


    q1,q2 = fermat(n)
    print(q1)
    print(q2)
