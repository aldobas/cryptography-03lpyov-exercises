import base64
import json
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

msg = b'This is the message to use to compute the HMAC'
key = get_random_bytes(32)
hmac_gen = HMAC.new(key, digestmod=SHA256)
hmac_gen.update(msg[:10])
hmac_gen.update(msg[10:])
mac = hmac_gen.hexdigest()

json_dict = {"message": msg.decode('utf-8'), "MAC":mac}
json_object  = json.dumps(json_dict)
print(json_object)



# ASSUMPTION: we have securely exchanged the secret key

b64 = json.loads(json_object)
hmac_ver = HMAC.new(key, digestmod=SHA256)
hmac_ver.update(b64["message"].encode('utf-8'))

try:
    hmac_ver.hexverify(b64["MAC"])
    print("The message '%s' is authentic" % msg)
except ValueError:
    print("The message or the key is wrong")
