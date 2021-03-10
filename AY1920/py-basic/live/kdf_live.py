#KDF password: string --> key (proper size) + add entropy --> salt
# KDF must be slow (dictionary attacks) and use a lot of RAM (dictionary attacks made with GPU or ASIC/FPGA)
# bcrypt and scrypt --> competition (AES, SHA3, STREAM) -> argon2i
# sccrypt

from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

password = b'passw0rd1'
salt = get_random_bytes(16) # minimum size of the salt is 16 bytes

key = scrypt (password, salt, 32, N=2**14, r=8, p=1)

# N=2**14, r=8, p=1 for interactive logins
# N=2**20, r=8, p=1 forkeys for encryption algorithm (disk encryption, file encryption)
