from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, constant_time
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Protocol.KDF import HKDF as HKDF_pycrypto


# Generate DH parameters
parameters = dh.generate_parameters(generator=2, key_size=1024,backend=default_backend())
#share them with the other party

# Generate a private key for use in the exchange.
server_private_key = parameters.generate_private_key()
server_public_key = server_private_key.public_key()

# this is the other party private key
# parameters have been shared in some way
peer_private_key = parameters.generate_private_key()
peer_public_key = peer_private_key.public_key()



#generate the shared material
shared_key = server_private_key.exchange(peer_public_key)
print(shared_key)

salt = get_random_bytes(16)
#it's not a password: scrypt not appropriate
# key1 = scrypt(shared_key, salt, 16, N=2**14, r=8, p=1)
# print(key1)
#HMAC pycryptodome
hkey1 = HKDF_pycrypto(shared_key, 32, salt, SHA512, 1)

# hazmat
kdf1 = HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b'handshake data',backend=default_backend())
derived_key = kdf1.derive(shared_key)
print(derived_key)

############################################################33
# same computation on the other party
same_shared_key = peer_private_key.exchange(server_public_key)

#script
# key2 = scrypt(shared_key, salt, 16, N=2**14, r=8, p=1)
#HMAC hazmat
kdf = HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b'handshake data',backend=default_backend())
same_derived_key = kdf.derive(same_shared_key)

#HMAC pycryptodome
#salt share
hkey2 = HKDF_pycrypto(shared_key, 32, salt, SHA512, 1)
print(hkey1)
print(hkey1)

# CHECK
print(constant_time.bytes_eq(hkey1, hkey2))
print(constant_time.bytes_eq(derived_key, same_derived_key))
# print(constant_time.bytes_eq(key1, key2))
# print(constant_time.bytes_eq(hkey1[0], hkey2[0]))
# print(constant_time.bytes_eq(hkey1[1], hkey2[1]))

#NEXT EXCHANGE: generate new private keys, do not reuse them

server_private_key2 = parameters.generate_private_key()
server_public_key2 = server_private_key2.public_key()

# this is the other party private key
peer_private_key2 = parameters.generate_private_key()
peer_public_key2 = peer_private_key2.public_key()

shared_key2= server_private_key2.exchange(peer_public_key2)
same_shared_key2= peer_private_key2.exchange(server_public_key2)
hkey1_2 = HKDF_pycrypto(shared_key2, 32, salt, SHA512, 1)
hkey2_2 = HKDF_pycrypto(same_shared_key2, 32, salt, SHA512, 1)
print(constant_time.bytes_eq(hkey1_2, hkey2_2))
