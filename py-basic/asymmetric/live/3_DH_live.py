from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, constant_time
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Protocol.KDF import HKDF as HKDF_pycrypto


# generate DH parameters
parameters = dh.generate_parameters(generator = 2, key_size = 1024, backend = default_backend())

# --> share these parameters with the other party

#generate the private key: random X
server_private_key = parameters.generate_private_key()
server_public_key = server_private_key.public_key()


# client: received parameters
client_private_key = parameters.generate_private_key()
client_public_key = client_private_key.public_key()


# beginning of the key exchange
# server sends server_public_key to client
# client sends client_public_key to server

server_shared_material = server_private_key.exchange(client_public_key)

#server
# private is x + (g,n)
# public is g^x mod n + (g,n)
# g ^ (xy) mod n
# client
# private is y + (g,n)
# public is g^y mod n + (g,n)

client_shared_material = client_private_key.exchange(server_public_key)


print(constant_time.bytes_eq(server_shared_material,client_shared_material))


# KDF functions to generate the actual keys
# scrypt --> not appropriate
# HMDF

# salt = get_random_bytes(16)
salt = b''
hkey_server = HKDF_pycrypto(server_shared_material, 32, salt, SHA512, 1)
hkey_client = HKDF_pycrypto(client_shared_material, 32, salt, SHA512, 1)
print(constant_time.bytes_eq(hkey_server,hkey_client))

# key_hazmat_server = HKDF(algorithm=hashes.SHA512(),length=32,salt=None,info=server_shared_material,backend=default_backend())
# key_hazmat_client = HKDF(algorithm=hashes.SHA512(),length=32,salt=None,info=client_shared_material,backend=default_backend())


##########################
# ephemeral: we never use again the same private key
# exchange on a private key --> drop it!
##########################
server_private_key_2 = parameters.generate_private_key()
server_public_key_2 = server_private_key_2.public_key()

client_private_key_2 = parameters.generate_private_key()
client_public_key_2 = client_private_key_2.public_key()

server_shared_material_2 = server_private_key_2.exchange(client_public_key_2)
client_shared_material_2 = client_private_key_2.exchange(client_public_key_2)
hkey_server2 = HKDF_pycrypto(server_shared_material, 32, salt, SHA512, 1)
hkey_client2 = HKDF_pycrypto(client_shared_material, 32, salt, SHA512, 1)
print(constant_time.bytes_eq(hkey_server2,hkey_client2))
