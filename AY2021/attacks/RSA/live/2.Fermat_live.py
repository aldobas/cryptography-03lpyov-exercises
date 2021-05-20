from gmpy2 import isqrt, next_prime
from Crypto.Util.number import getPrime
from sympy import nextprime

# write fermat(n)
def fermat(n):

    print("init")
    a = isqrt(n)
    b = a
    b2_approx = pow(a,2) - n

    print("a="+str(a))
    print("b=" + str(b))


    print("main cycle")
    i = 0

    while True:
        if b2_approx == pow(b,2):
            print("Fount at iteration "+str(i))
            break;
        else:
            a += 1
            b2_approx = pow(a,2)-n
            b = isqrt(b2_approx)

        i+=1
        print("iteration "+str(i))
        print("a=" + str(a))
        print("b=" + str(b))

    p = a + b
    q = a - b

    return p,q

# main
# generate primes with small delta

if __name__ == '__main__':

    n_len = 500


    p1 = getPrime(n_len) # the first one
    delta = getPrime(262)

    p2 = next_prime(p1+delta)               # second one close to p1

    n = p1*p2

    print("p1="+str(p1))
    print("p2="+str(p2))
    print("n ="+str(n))

    p,q = fermat(n)
    print("p=" + str(p))
    print("q=" + str(q))
