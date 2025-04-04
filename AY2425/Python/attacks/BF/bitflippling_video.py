from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

if __name__ == '__main__':

    plaintext = b'This is the message to encrypt but the attacker knows there is a specific sequence of numbers 12345'
    #attacker knows that b'1' in a specific position
    index = plaintext.index(b'1')
    print(index)

    key = get_random_bytes(32)
    nonce = get_random_bytes(12)
    cipher = ChaCha20.new(key = key, nonce = nonce)
    ciphertext = cipher.encrypt(plaintext)

    # ciphertext, index, b'1'

    new_value = b'9'
    new_int = ord(new_value) # ASCII code

    mask = ord(b'1') ^ new_int

    edt_ciphertext = bytearray(ciphertext)
    edt_ciphertext[index] = ciphertext[index] ^ mask

    # edt_ciphertext is received by the recipient,

    cipher_dec = ChaCha20.new(key=key, nonce=nonce)
    decrypted_text = cipher_dec.decrypt(edt_ciphertext)
    print(decrypted_text)
