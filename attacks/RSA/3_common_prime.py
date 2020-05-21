from Crypto.Util.number import getPrime


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

p1 = getPrime(20)
p2 = getPrime(20)
p3 = getPrime(20)
print(p1)
print(p2)
print(p3)

n1 = p1 * p2
n2 = p1 * p3

print(n1)
print(n2)


f1 = egcd(n1,n2)[0]

f2 = n1 // f1

f3 = n2 // f1


print(f1)
print(f2)
print(f3)
