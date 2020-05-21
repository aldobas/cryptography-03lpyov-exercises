from Crypto.PublicKey import RSA

e = 65537
key1 = RSA.generate(1024,e=e)

print(key1)


pair = (key1.e,key1.n)
print(pair)

pubkey = key1.publickey()
print(pubkey)
