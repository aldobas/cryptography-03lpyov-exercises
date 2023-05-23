from Crypto.Util.number import getPrime
from factordb.factordb import FactorDB

n_length = 150

p1 = getPrime(n_length)
p2 = getPrime(n_length)
print(p1)
print(p2)

n = p1 * p2
print(n)



f = FactorDB(n)
f.connect()
print(f.get_factor_list())
