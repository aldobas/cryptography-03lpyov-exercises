from srptools import SRPContext, SRPServerSession, SRPClientSession


username = 'aldo'
password = 'my very strong password'

### at the client, where the password is known

srp_context = SRPContext(username,password) # gen, prime
user, password_verifier, salt = srp_context.get_user_data_triplet()
gen = srp_context.generator
prime = srp_context.prime

#####
# HERE WE ARE IN THE SERVER
# client send the server user, password_verifier, salt, gen, prime
server_context = SRPContext(username, prime=prime, generator=gen)

###########
# authentication starts here
server_session = SRPServerSession(server_context, password_verifier)

server_public_B = server_session.public # to be sent to the client


#####
# HERE WE ARE IN THE CLIENT
client_session = SRPClientSession(srp_context)
client_public_A = client_session.public



# the client has received B
# the server has received A


#####
# HERE WE ARE IN THE SERVER
server_session.process(client_public_A,salt) # generating the common secret

server_key_proof = server_session.key_proof
server_key_proof_hash = server_session.key_proof_hash
print(server_key_proof)
print(server_key_proof_hash)

#####
# HERE WE ARE IN THE CLIENT
client_session.process(server_public_B,salt) #generating the common secret

client_key_proof = client_session.key_proof
client_key_proof_hash = client_session.key_proof_hash
print(client_key_proof)
print(client_key_proof_hash)

#####
# HERE WE ARE IN THE SERVER
assert server_session.verify_proof(client_key_proof)


#####
# HERE WE ARE IN THE CLIENT
assert client_session.verify_proof(server_key_proof_hash)
