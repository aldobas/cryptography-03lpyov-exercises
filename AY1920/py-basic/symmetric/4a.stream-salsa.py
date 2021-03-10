from Crypto.Cipher import Salsa20

key = b'deadbeefdeadbeef'
cipher = Salsa20.new(key)
ciphertext =  cipher.encrypt(b'The secret I want to send. ')
ciphertext += cipher.encrypt(b'The second part of the secret.')
nonce = cipher.nonce
print(nonce)

cipher2 = Salsa20.new(key,nonce)
plaintext = cipher2.decrypt(ciphertext)
print("Decrypted = "+plaintext.decode("utf-8"))

