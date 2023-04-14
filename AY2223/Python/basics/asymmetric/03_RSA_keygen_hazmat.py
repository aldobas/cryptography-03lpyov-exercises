from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
    )


pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8, # RAW / Traditional OpenSSL
    # encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword')
    encryption_algorithm=serialization.NoEncryption()
    )
# pem.splitlines()[0]
print(pem)
with open("privatekey.pem", 'wb') as pem_out:
        pem_out.write(pem)



public_key = private_key.public_key()
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
print(public_pem)
print(public_key.public_numbers())
print(private_key.private_numbers().p)
print(private_key.private_numbers().q)
print(private_key.private_numbers().d)

print(private_key.private_numbers().public_numbers.e)
