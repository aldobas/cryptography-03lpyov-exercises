from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256

#gen parameters: generator and the modulus (prime)
param = dh.generate_parameters(generator=2, key_size=512 )

# server:alice: generates the private part: x
server_private_key = param.generate_private_key()
# print(server_private_key.parameters().parameter_numbers().g)
# print(server_private_key.parameters().parameter_numbers().p)
# p = server_private_key.parameters().parameter_numbers().p
# print(server_private_key.parameters().parameter_numbers().q) #?
# print(server_private_key.private_numbers().x)
# x = server_private_key.private_numbers().x

# A = g^x mod p
server_public_key = server_private_key.public_key()
# print(server_public_key.public_numbers().y)
# y = server_public_key.public_numbers().y
#
# print(pow(2,x,p))

# send to the other party
#gen server private and public parameters




#gen client private and public parameters
# received the parameters param
client_private_key = param.generate_private_key()
client_public_key = client_private_key.public_key()


# simulate the key exchange
# server receives client_public_key
# client receives server_public_key

#[ A y --> A ^ y mod p == B ^ x mod p ]
server_secret = server_private_key.exchange(client_public_key)

client_secret = client_private_key.exchange(server_public_key)
# have enough entropy: good random numbers already

if bytes_eq(client_secret,server_secret):
    print("same secret")
else:
    print("different secret")

# generate key from shared secrets
# use a KDF --> from bytes not passwords --> HKDF
# keys from passwords require a salt --> increase randomness
# scrypt is not really needed

s_key = HKDF(algorithm=SHA256(), length = 16, salt = None, info=server_secret).derive(b'')
for i in range(4):
    print(HKDF(algorithm=SHA256(), length=16, salt=None, info=server_secret).derive(i.to_bytes(1,byteorder='big')))
print(s_key)

c_key = HKDF(algorithm=SHA256(), length = 16, salt = None, info=client_secret).derive(b'')

if bytes_eq(s_key,c_key):
    print("same secret")
else:
    print("different secret")

#### ephemeral
server_private_key2 = param.generate_private_key()
second_public = server_private_key2.public_key()

# server_private_key2.exchange(new_material_from_client)
