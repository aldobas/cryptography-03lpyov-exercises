from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

password = b'W34kpassw0rd!'
salt = get_random_bytes(16)

# A good choice of parameters (N, r , p) was suggested by Colin Percival in his presentation in 2009:
# http://www.tarsnap.com/scrypt/scrypt-slides.pdf
# ( 2¹⁴, 8, 1 ) for interactive logins (≤100ms)
# ( 2²⁰, 8, 1 ) for file encryption (≤5s)

key = scrypt(password, salt, 16, N=2**14, r=8, p=1)
print(salt)

print("This should be secret: " + str(key))
