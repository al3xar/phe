#!/bin/bash
# Script para compilar echosrv.c con los requisitos específicos

# Compilar con:
# - 32 bits (-m32)
# - NX habilitado (por defecto)
# - ASLR se habilitado

gcc -m32 -o echosrv echosrv.c