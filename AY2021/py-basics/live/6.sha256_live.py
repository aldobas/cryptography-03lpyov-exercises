from Crypto.Hash import SHA256


#init a SHA256 object with initial data
hash_gen = SHA256.new(data=b'Even before the first part. ')
hash_gen.update(b'This is the first part. ')
hash_gen.update(b'This is the second part. ')

print(hash_gen.hexdigest())
print(hash_gen.digest())


#update data and print new values

