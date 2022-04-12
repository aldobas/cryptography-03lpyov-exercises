import hashlib
import hmac
from Crypto.Random import get_random_bytes

msg = b'This is the message'
secret = get_random_bytes(32)


blake = hashlib.blake2b(key=secret, digest_size=32)
blake.update(msg)
print("BLAKE = " + blake.hexdigest())

####################
# the sender is computing the HMAC...
mac_factory = hmac.new(secret, msg, hashlib.sha256)
hmac_sha256 = mac_factory.digest()

print("HMAC-SHA256@SENDER   = " + mac_factory.hexdigest())


# the receiver has received msg1 and hmac_sha256...
# then checks the HMAC
msg1 = b'This is the new message'
mac_factory_receiver = hmac.new(secret, msg1, hashlib.sha256)
hmac_sha256_1 = mac_factory_receiver.hexdigest()
print("HMAC-SHA256@RECEIVER= " + hmac_sha256_1)

if hmac.compare_digest(mac_factory_receiver.digest(), hmac_sha256):
    print("HMAC correctly verified: messages are identical")
else:
    print("HMAC are different")
