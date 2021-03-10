from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

key_file = open("privatekey.pem", "rb")
private_key = serialization.load_pem_private_key(
    key_file.read(),
    password=None,
    backend=default_backend()
)

public_key = private_key.public_key()

message = b"encrypted data"

ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
# plaintext == message

print(constant_time.bytes_eq(plaintext,message))
