import base64
import json
from Crypto.Hash import HMAC, SHA512
from Crypto.Random import get_random_bytes

msg = b'This is the message to use. Now compute the SHA512-HMAC'
secret = get_random_bytes(32)
hmac_gen = HMAC.new(secret, digestmod=SHA512)
hmac_gen.update(msg[:10])
hmac_gen.update(msg[10:])
mac = hmac_gen.hexdigest()


#store message and MAC into a JSON data structure
json_dict = {"message": msg.decode(), "MAC":mac}
json_object  = json.dumps(json_dict)
print(json_object)



# ASSUMPTION: we have securely exchanged the secret

b64 = json.loads(json_object)
hmac_ver = HMAC.new(secret, digestmod=SHA512)
hmac_ver.update(b64["message"].encode())

try:
    hmac_ver.hexverify(b64["MAC"])
    print("The message '%s' is authentic" % msg)
except ValueError:
    print("Wrong secret or message.")
