from pwn import *

e = ELF("secure_bank")
p = e.process()

#gdb.attach(p,"""
#    break main
#           """)
p = remote("securebank.ctf.intigriti.io", 1335)
print(p.recv())
payload1 = 0x539
p.sendline(str(int(payload1)))
#print(p.recv())
code = 0x568720
p.sendline(str(int(code)))
print(p.recv())
print(p.recv())
print(p.recv())

print(p.recv())
