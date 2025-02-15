from pwn import *
import ctypes
import time

# Load the C standard library
libc = ctypes.CDLL("/lib/x86_64-linux-gnu/libc.so.6")  # On Linux
# libc = ctypes.CDLL("msvcrt.dll")  # On Windows

cookie_offset = 0x00003008
elf = ELF("main")

cookies = elf.read(cookie_offset, 16*100).split(b'\x00')
print(cookies)
print(len(cookies))
# Seed the random number generator with the current time
tVar2 = int(time.time())
libc.srand(tVar2)
#p = elf.process()
p = remote("20.244.40.210", 6000)

for i in range(100):
    ret = p.recvuntil("Guess the cookie: ")
    print(ret)
    rnd = libc.rand()
    #print(rnd)
    i = rnd%100
    #print(i)
    #print(cookies[i])
    p.sendline(cookies[i])
    #print(p.recv())

print(p.recv())
print(p.recv())

#BITSCTF{7h4nk5_f0r_4ll_0f_th3_c00ki3s_1_r34lly_enjoy3d_th3m_d31fa51e}

