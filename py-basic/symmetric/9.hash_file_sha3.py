from Crypto.Hash import SHA3_256
import sys

hash_object = SHA3_256.new()

with open(sys.argv[1],"rb") as f_input:
    input_data = f_input.read(1024)
    hash_object.update(input_data)


print(hash_object.digest())
print(hash_object.hexdigest())
