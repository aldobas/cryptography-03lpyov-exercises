from Crypto.Hash import SHA256


hash_object = SHA256.new()
hash_object.update(b'Beginning of the message to hash...')
hash_object.update(b'...and some more data')

print(hash_object.digest())
print(hash_object.hexdigest())


hash_object = SHA256.new(data=b'First part of the message. ' )
hash_object.update(b'Second part of the message. ')
hash_object.update(b'Third and last.')

print(hash_object.digest())
print(hash_object.hexdigest())
