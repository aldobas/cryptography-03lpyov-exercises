from Crypto.Cipher import AES
import os

from Crypto.Random import get_random_bytes

os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *
from srptools import SRPContext, SRPClientSession
from base64 import b64encode, b64decode
import json

from mysecrets import HOST,PORT, cbc_oracle_iv as iv
from mysecrets import cbc_oracle_ciphertext as ciphertext

DATA_SIZE = 65535

USERNAME = 'aldo'
PASSWORD = 'safe_passwd'


if __name__ == '__main__':


    # the user should receive the salt from the server, before generating the context

    context = SRPContext(USERNAME, PASSWORD)
    username, password_verifier, client_salt = context.get_user_data_triplet()
    print(username)
    print(password_verifier)
    print(client_salt)
    prime = context.prime
    gen = context.generator

    print(prime)
    print(gen)


    server = remote(HOST, PORT)

    auth_data = json.dumps({'username': username, 'prime': prime, 'generator': gen, 'password_verifier': password_verifier, 'salt': client_salt})
    print(auth_data)
    server.send(auth_data.encode())

    #receive server verifier and salt
    received_data = server.recv(DATA_SIZE).decode()
    server_data = json.loads(received_data)
    print(server_data)
    print("server public= "+str(server_data['server_verifier']))
    # print("server salt  = "+str(server_data['salt']))

    #compute client parameters
    client_session = SRPClientSession(context)
    client_session.process(server_data['server_verifier'], client_salt)

    # Generate client public and session key proof.
    client_public = client_session.public
    print("client public = "+str(client_public))
    client_session_key_proof = client_session.key_proof.hex()
    print("session key proof = " + str(client_session_key_proof))
    print("session key proofB= " + str(client_session.key_proof))
    client_parameters = json.dumps({'client_parameter': client_public, 'session_key_proof': client_session_key_proof})
    server.send(client_parameters.encode())


    print(client_session.key)

    # Generate session key proof hash
    # server_session_key_proof_hash = client_session.key_proof_hash
    # assert client_session.verify_proof(server_session_key_proof_hash)


    server.close()
