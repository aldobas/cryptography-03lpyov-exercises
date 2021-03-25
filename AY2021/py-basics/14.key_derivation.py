from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

password = b'passw0rd!'
salt = get_random_bytes(16)
key = scrypt(password, salt, 16, N=2**14, r=8, p=1)
print(salt)

print("This should be secret: " + str(key))
