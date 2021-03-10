import json
from base64 import b64encode,b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytesjson_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
json_v = [ b64encode(x).decode('utf-8') for x in (cipher.nonce, header, ciphertext, tag) ]
json_object  = json.dumps(dict(zip(json_k, json_v)))
print(json_object)


AES256_KEY_SIZE=32

header = b"this is the authentication only part"
data = b"this is the secret part"

key = get_random_bytes(AES256_KEY_SIZE)
cipher = AES.new(key, AES.MODE_GCM)
cipher.update(header) #this is to load the data to authenticate
ciphertext, tag = cipher.encrypt_and_digest(data) # this is to add the data to also encrypt

json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
json_v = [ b64encode(x).decode('utf-8') for x in (cipher.nonce, header, ciphertext, tag) ]
json_object  = json.dumps(dict(zip(json_k, json_v)))
print(json_object)


try:
    b64 = json.loads(json_object)
    json_k = ['nonce','header','ciphertext','tag']
    jv = {k:b64decode(b64[k]) for k in json_k}

    cipher2 = AES.new(key, AES.MODE_GCM, nonce=jv['nonce'])
    cipher2.update(jv['header'])
    plaintext = cipher2.decrypt_and_verify(jv['ciphertext'], jv['tag'])
    print("The message was: " + plaintext.decode('utf-8')+" and is authentic.")
except (ValueError, KeyError):
    print("Incorrect decryption")
