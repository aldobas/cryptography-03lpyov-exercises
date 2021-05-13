
# KDF: takes a password --> generates a good key
# salt: freshness + statistical reasons
# delay attackers: iteration  + increase the memory used: no dictionary

from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

password = b'passw0rd!'
salt = get_random_bytes(16) # at least 16 bytes

key = scrypt(password, salt, 32, N=2**20, r=8, p=1)

print(key)

# N=2**14, r=8, p=1 for interactive logins
# N=2**20, r=8, p=1 for generating keys for encryption algorithm (disk encryption, file encryption)
