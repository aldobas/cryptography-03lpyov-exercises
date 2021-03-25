from Crypto.Hash import SHA256

hash_object = SHA256.new(data=b'First part of the message. ' )
hash_object.update(b'Second part of the message. ')
hash_object.update(b'Third and last.')
# update in OpenSSL

print(hash_object.digest())
print(hash_object.hexdigest()) #finalize
