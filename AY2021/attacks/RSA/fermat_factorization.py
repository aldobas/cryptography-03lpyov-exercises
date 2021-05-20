from gmpy2 import isqrt
from Crypto.Util.number import getPrime
from gmpy2 import next_prime


def fermat(n):
    print("init")

    a = isqrt(n)
    b = a
    b2 = pow(a,2) - n

    print("a= "+str(a))
    print("b= " + str(b))

    print("iterate")
    i = 0

    while True:
        if b2 == pow(b,2):
            print("found at iteration "+str(i))
            break;
        else:
            a +=1
            b2 = pow(a, 2) - n
            b = isqrt(b2)
        i+=1
        print("iteration="+str(i))
        print("a= " + str(a))
        print("b= " + str(b))

    p = a+b
    q = a-b

    return p,q

if __name__ == '__main__':

    n = 400
    delta = getPrime(220)


    p1 = getPrime(n)
    p2 = next_prime(p1+delta)
    print(p1)
    print(p2)
    print(p2-p1)

    n = p1*p2

    p,q = fermat(n)

    print("p = "+str(p))
    print("q = " + str(q))
