#!/bin/bash
# Script para compilar echosrv.c con los requisitos específicos

# Compilar con:
# - 32 bits (-m32)
# - NX habilitado (por defecto)
# - ASLR deshabilitado

gcc -o echosrv64 echosrv64.c