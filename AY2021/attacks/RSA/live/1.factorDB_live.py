from Crypto.Util.number import getPrime
from factordb.factordb import FactorDB


# generate primes
# compute n
n_len = 256

p1 = getPrime(n_len)
p2 = getPrime(n_len)

n = p1*p2

print("p1="+str(p1))
print("p2="+str(p2))
print("n ="+str(n))

# use factor DB

fdb = FactorDB(n)
fdb.connect()
res = fdb.get_factor_list()

print(res)


# use yafu instead!
