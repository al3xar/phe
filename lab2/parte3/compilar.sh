#!/bin/bash
# Script para compilar echosrv.c con los requisitos específicos

# Compilar con:
# - 32 bits (-m32)
# - NX habilitado (por defecto)
# - Sin SSP (-fno-stack-protector)
# - ASLR se habilita durante la ejecución, no durante la compilación

gcc -m32 -fno-stack-protector -o echosrv echosrv.c

echo "Compilación completa. Para ejecutar con ASLR habilitado, no se requiere ninguna acción especial."
echo "Puedes verificar el estado del ASLR con: cat /proc/sys/kernel/randomize_va_space"
echo "Si muestra 1 o 2, el ASLR está habilitado."
