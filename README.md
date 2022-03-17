# Tiny AES
Tiny AES is a smol AES-128 EBC encryption library (with hardware acceleration for x86-64, and aarch64 on the way)

## Building

To build a harware-optimized version, run the following command...
```
$ ENABLE_ASM_STUBS=1 make
```

To build a standard, software-only version, run the following command...
```
$ make
```

Finally, to generate embeddable single C source file and header (no native acceleration), run the following...
```
$ make pack
$ cp tinyaes_all.c tinyaes_all.h <project-dir>
```

