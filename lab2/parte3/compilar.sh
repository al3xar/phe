#!/bin/bash
# Script para compilar echosrv.c con los requisitos específicos

# Compilar con:
# - 32 bits (-m32)
# - NX habilitado (por defecto)
# - Sin SSP (-fno-stack-protector)
# - ASLR se habilita durante la ejecución, no durante la compilación

gcc -m32 -fno-stack-protector -o echosrv echosrv.c