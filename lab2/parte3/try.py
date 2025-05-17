# Genera direcciones del tipo 0xf7XXX220, donde XXX va de 0x00000 a 0xFFFFF

start = 0xF7000220
end = 0xF7FFFF20  # Última dirección válida antes de pasarse del patrón

current = start

while current <= end:
    # Mostrar dirección en hexadecimal
    print(f"Dirección: {hex(current)}")

    # Si también quieres mostrarla en little endian:
    little_endian = current.to_bytes(4, byteorder="little")
    escaped = "".join(f"\\x{b:02x}" for b in little_endian)
    print(f"  Little endian: {escaped}")

    # Incrementa 0x010000 (que equivale a incrementar el campo XXX en +1)
    current += 0x010000
