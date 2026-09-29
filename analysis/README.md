# Как получено дизассемблирование

Из корня репозитория:

```bash
clang --target=arm-none-eabi -mcpu=cortex-m0plus -mthumb -c analysis/firmware.S -o firmware.o
objdump -d firmware.o > firmware-full-disassembly.txt
```

В объект помещены первые 0x7000 байт реального дампа. Адреса objdump здесь являются смещениями в flash.bin. Адрес RP2040 равен 0x10000000 плюс это смещение.
