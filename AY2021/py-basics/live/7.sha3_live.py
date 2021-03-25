from Crypto.Hash import SHA3_256

hash_gen = SHA3_256.new()

with open("./6.sha256_live.py","rb") as f_input:
     hash_gen.update(f_input.read())


print(hash_gen.digest())
print(hash_gen.hexdigest())

