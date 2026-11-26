# C/C++ → Intel x86 (32-bit) Assembly Pattern Reference

This file is for reverse engineering on Windows x86, with OSED in mind.

**Conventions used in this file**

* Syntax is **Intel**, as in IDA, WinDbg and x32dbg: `mov dst, src`.
* The baseline is **MSVC `/Od` (unoptimized)**, because that is the easiest to read. Optimized (`/O2`) forms are shown where they look very different. You will meet both.
* Locals are at `[ebp-N]`. Arguments are at `[ebp+8]`, `[ebp+0Ch]`, … under an EBP frame. In optimized code without a frame pointer (FPO), they are at `[esp+N]`.
* Symbol names use MSVC decoration: `_func` (cdecl), `_func@8` (stdcall), `@func@8` (fastcall), `?method@Class@@...` (C++).
* Sections marked ★ were added after cross-checking this file against firmianay's x86 notes on *Practical Reverse Engineering* (https://github.com/firmianay/Life-long-Learner/blob/master/practical-reverse-engineering/RE_Learning_x86_x64.md). The x64 part of those notes is left out on purpose: this file is 32-bit x86 only.
* Exact register choice and instruction order vary between compiler versions. Learn the **shape** of each pattern, not the exact bytes.

---

## 0. x86 architecture fundamentals ★

### 0.1 Modes, privilege rings, endianness

* **Real mode** is the 16-bit state the CPU starts in at power-on. **Protected mode** is the 32-bit state with paging and virtual memory, which is where Windows runs. 32-bit programs on 64-bit Windows (WoW64) still execute exactly this 32-bit x86 code, so everything here applies to them.
* **Privilege rings 0–3.** Windows uses ring 3 for user mode (your OSED targets) and ring 0 for the kernel. The current privilege level (CPL) is held in the low 2 bits of `CS`. User code can't simply load a new `CS` to raise its privilege, because every far transfer is checked by the CPU against segment and gate descriptors. The only ways into ring 0 are controlled entry points such as `sysenter`, `int 2Eh` and interrupt or exception gates.
* **Little-endian.** The value `0x11223344` is stored in memory as the bytes `44 33 22 11`. This is why the address `0x625011AF` goes into a payload as `\xAF\x11\x50\x62`, and why WinDbg's `dd` (dwords) and `db` (bytes) show the same memory in opposite byte orders.

### 0.2 Registers

| Register | Conventional role | Notes for RE / exploit dev |
|---|---|---|
| `EAX` | accumulator; **return value**; `mul`/`div` operand | after a call, follow EAX |
| `EBX` | general purpose, callee-saved | survives calls |
| `ECX` | **counter** (`rep`, `loop`, shift count in `CL`); **`this`** in thiscall | |
| `EDX` | high half for `mul`/`div` (`EDX:EAX`); 2nd fastcall argument | |
| `ESI` | **source** pointer for string instructions | callee-saved |
| `EDI` | **destination** pointer for string instructions | callee-saved |
| `EBP` | frame pointer (`[ebp+x]` args, `[ebp-x]` locals) | callee-saved; saved copy sits next to the return address |
| `ESP` | stack pointer (top of stack) | `jmp esp` / `push esp; ret` land here |
| `EIP` | instruction pointer | **not** directly readable or writable; changed only by control-transfer instructions (`jmp`, `call`, `ret`, `jcc`, `loop` …), interrupts and exceptions |

Sub-registers:

```
EAX = [ 16 high bits | AX = [ AH | AL ] ]      (same for EBX/BX/BH/BL, ECX, EDX)
ESI -> SI,  EDI -> DI,  EBP -> BP,  ESP -> SP  (no 8-bit parts in 32-bit mode)
```

Writing `AL` leaves the upper 24 bits of EAX unchanged, which is why compilers follow byte operations with `movzx eax, al`.

The segment registers are `CS DS SS ES FS GS`. On Windows x86, **`FS` points to the TEB** (§12.4).

**Volatile vs callee-saved:** `EAX`, `ECX` and `EDX` may be destroyed by any call. `EBX`, `ESI`, `EDI` and `EBP` must be preserved, which is why you see them pushed in the prologue and popped in the epilogue (§2.9).

### 0.3 EFLAGS

| Flag | Bit | Set when … |
|---|---|---|
| CF (carry) | 0 | unsigned overflow or borrow; also the bit shifted out, or the bit tested by `bt` |
| PF (parity) | 2 | low byte of the result has an even number of 1 bits (used in x87 compare tricks) |
| ZF (zero) | 6 | result is 0 |
| SF (sign) | 7 | top bit of the result is 1 |
| TF (trap) | 8 | single-step (debuggers) |
| DF (direction) | 10 | 0 means string instructions move **forward** (`cld`, the normal state); 1 means backward (`std`) |
| OF (overflow) | 11 | signed overflow |

`cmp a, b` computes `a - b`, sets the flags and discards the result. `test a, b` computes `a & b`, sets the flags and discards the result.

What each conditional jump actually tests:

| Jcc | Condition | Use |
|---|---|---|
| `je`/`jz` | ZF=1 | equal |
| `jne`/`jnz` | ZF=0 | not equal |
| `jb`/`jc`/`jnae` | CF=1 | unsigned < |
| `jae`/`jnb`/`jnc` | CF=0 | unsigned ≥ |
| `jbe`/`jna` | CF=1 or ZF=1 | unsigned ≤ |
| `ja`/`jnbe` | CF=0 and ZF=0 | unsigned > |
| `jl`/`jnge` | SF≠OF | signed < |
| `jge`/`jnl` | SF=OF | signed ≥ |
| `jle`/`jng` | ZF=1 or SF≠OF | signed ≤ |
| `jg`/`jnle` | ZF=0 and SF=OF | signed > |
| `js` / `jns` | SF=1 / SF=0 | negative / non-negative |
| `jo` / `jno` | OF=1 / OF=0 | signed overflow |
| `jp` / `jnp` | PF=1 / PF=0 | parity (x87 compares, NaN checks) |
| `jecxz` | ECX=0 | skip a loop when the count is 0 |

Remember: "above/below" means **unsigned**, and "greater/less" means **signed**.

### 0.4 Data sizes

| Name | Size | Register example | MASM declaration | Pointer keyword |
|---|---|---|---|---|
| byte | 8 bit | `AL` | `db` | `byte ptr` |
| word | 16 bit | `AX` | `dw` | `word ptr` |
| dword | 32 bit | `EAX` | `dd` | `dword ptr` |
| qword | 64 bit | `EDX:EAX` pair, x87/SSE | `dq` | `qword ptr` |
| tbyte | 80 bit | x87 extended | `dt` | `tbyte ptr` |

### 0.5 Instruction encoding: bytes worth recognizing

x86 instructions are **1 to 15 bytes** long, and decoding can start at any byte. That is why a gadget can hide inside another instruction, and why disassembly can go wrong after embedded data.

| Bytes | Instruction | Why it matters |
|---|---|---|
| `90` | `nop` | NOP sleds / padding |
| `CC` | `int 3` | breakpoint; MSVC padding between functions |
| `C3` | `ret` | end of every gadget |
| `C2 xx xx` | `ret imm16` | stdcall return |
| `FF E4` | `jmp esp` | classic EIP → stack pivot |
| `FF D4` | `call esp` | same idea |
| `54 C3` | `push esp ; ret` | same idea |
| `58`–`5F` | `pop eax` … `pop edi` | `pop r32 ; pop r32 ; ret` is the SEH gadget (e.g. `5E 5F C3`) |
| `50`–`57` | `push eax` … `push edi` | |
| `EB xx` | `jmp short rel8` | `EB 06` is the classic nSEH short jump |
| `E9 xx xx xx xx` | `jmp rel32` | |
| `E8 xx xx xx xx` | `call rel32` | `E8 00 00 00 00` is `call $+5` (GetPC, §2.8) |
| `74 xx` / `75 xx` | `jz` / `jnz short` | |
| `68 imm32` / `6A imm8` | `push imm32` / `push imm8` | |
| `31 C0` / `33 C0` | `xor eax, eax` | two valid encodings |
| `66` prefix | operand-size override | switches to a 16-bit operand |
| `F3` / `F2` prefix | `rep`/`repe` / `repne` | |
| `64` prefix | `FS:` segment override | `64 A1 30 00 00 00` is `mov eax, fs:[30h]` |

---

## 1. Stack frame basics

### 1.1 Prologue / epilogue

```c
int f(int a, int b) {
    int x;
    char buf[16];
    ...
    return x;
}
```

```asm
_f:
    push    ebp                 ; save caller's frame pointer
    mov     ebp, esp            ; new frame
    sub     esp, 14h            ; space for locals (x + buf = 4 + 16)
    ...
    mov     eax, [ebp-4]        ; return value in EAX
    mov     esp, ebp            ; } often a single 'leave'
    pop     ebp                 ; }
    ret                         ; cdecl: caller cleans args
```

Stack layout after the prologue:

```
[ebp+0Ch]  b            (2nd arg)
[ebp+8]    a            (1st arg)
[ebp+4]    return address   <- the EIP overwrite target
[ebp]      saved EBP
[ebp-4]    x  (or the /GS cookie under /GS)
[ebp-14h]  buf[16]
```

With `/GS` on, MSVC puts arrays directly below the cookie and moves scalars and pointers below the arrays.

### 1.2 Hot-patchable prologue (Windows system DLLs)

```asm
    mov     edi, edi            ; 2-byte NOP used for hot patching
    push    ebp
    mov     ebp, esp
```

### 1.3 Frame pointer omission (optimized)

```asm
_f:
    sub     esp, 14h
    mov     eax, [esp+18h]      ; arg 'a' = esp + localsize + 4 (ret addr)
    ...
    add     esp, 14h
    ret
```

Offsets from ESP shift every time something is `push`ed. Use IDA's stack-pointer view (`Options → General → Stack pointer`) to keep track.

### 1.4 Large frames: `_chkstk` / `_alloca_probe`

```c
void big(void) { char buf[0x2000]; ... }
```

```asm
    push    ebp
    mov     ebp, esp
    mov     eax, 2000h
    call    __chkstk            ; touches each page (guard-page probing), then sets ESP
```

A frame larger than one page (4 KB) causes a `__chkstk` call. Seeing it usually means a big stack buffer, which is worth checking for overflows.

### 1.5 Return values

| C return type | Location |
|---|---|
| `int`, pointer, `char`, `short`, `bool` | `EAX` (`AL`/`AX` for small types; check `movzx`/`movsx` at the caller) |
| `long long` / `__int64` | `EDX:EAX` (EDX = high) |
| `float`, `double` | `ST(0)` (x87). Some modern code moves through SSE too, but the x86 ABI still returns in `ST(0)` |
| Struct ≤ 8 bytes | `EDX:EAX` (MSVC, for POD structs) |
| Larger struct | Caller passes a hidden pointer as the first argument. Callee fills it and returns that pointer in `EAX` |

---

## 2. Calling conventions

### 2.1 `__cdecl` (C default)

```c
int add(int a, int b);
r = add(1, 2);
```

```asm
    push    2                   ; args pushed right-to-left
    push    1
    call    _add
    add     esp, 8              ; CALLER cleans the stack
    mov     [ebp-4], eax
```

### 2.2 `__stdcall` (WinAPI / `WINAPI` / `CALLBACK`)

```c
MessageBoxA(NULL, "hi", "t", 0);
```

```asm
    push    0                   ; uType
    push    offset aT           ; "t"
    push    offset aHi          ; "hi"
    push    0                   ; hWnd
    call    ds:__imp__MessageBoxA@16   ; call through the IAT
                                ; no 'add esp' — the callee cleans up
```

Inside the callee:

```asm
    ret     10h                 ; pops 16 bytes of args (4 args × 4)
```

`ret N` is the clearest sign of stdcall, and `N / 4` gives the argument count.

### 2.3 `__fastcall`

```c
int __fastcall f(int a, int b, int c);
```

```asm
    push    3                   ; 3rd+ args on the stack
    mov     edx, 2              ; 2nd arg
    mov     ecx, 1              ; 1st arg
    call    @f@12
```

The callee uses ECX and EDX before writing to them, and ends with `ret 4` (cleaning only the stack args).

### 2.4 `__thiscall` (MSVC C++ member functions)

```cpp
obj.method(5);
```

```asm
    push    5
    lea     ecx, [ebp-10h]      ; ECX = this
    call    ?method@Obj@@QAEXH@Z
```

A function that reads ECX before writing it is almost certainly a C++ method or fastcall.

### 2.5 Variadic functions (always cdecl)

```c
printf("%d %s\n", n, s);
```

```asm
    mov     eax, [ebp-8]        ; s
    push    eax
    mov     ecx, [ebp-4]        ; n
    push    ecx
    push    offset aDS          ; "%d %s\n"
    call    _printf
    add     esp, 0Ch            ; caller cleans; size tells you the arg count
```

Inside a variadic function, `va_start(ap, fmt)` becomes `lea eax, [ebp+0Ch]` followed by `mov [ebp-ap], eax`, which is the address just past the last named argument. Each `va_arg(ap, int)` advances that pointer by 4 and reads the slot it just stepped over (`add ecx, 4` followed by `mov eax, [ecx-4]`).

### 2.6 Calling-convention cheat sheet

| Convention | Args | Cleanup | Hint in asm |
|---|---|---|---|
| cdecl | stack, R→L | caller `add esp, N` | plain `ret` |
| stdcall | stack, R→L | callee `ret N` | `ret N`, `@N` decoration |
| fastcall | ECX, EDX, then stack | callee | ECX/EDX read before being set |
| thiscall | ECX = this, rest on stack | callee | `lea/mov ecx, obj` before call |


### 2.7 PUSH / POP / CALL / RET mechanics ★

| Instruction | What the CPU does |
|---|---|
| `push x` | `ESP -= 4`, then `[ESP] = x` |
| `pop r` | `r = [ESP]`, then `ESP += 4` |
| `call target` | `push <address of next instruction>`, then `EIP = target` |
| `ret` | `EIP = [ESP]`, `ESP += 4` (effectively "pop eip") |
| `ret N` | as `ret`, then `ESP += N` (stdcall argument cleanup) |
| `leave` | `mov esp, ebp`, then `pop ebp` |

Tracing ESP through a call (starting at `ESP = 0019FF00h`):

```asm
    push    2           ; ESP = 0019FEFCh, [0019FEFC] = 2
    push    1           ; ESP = 0019FEF8h, [0019FEF8] = 1
    call    _add        ; ESP = 0019FEF4h, [0019FEF4] = return address
_add:
    push    ebp         ; ESP = 0019FEF0h, [0019FEF0] = caller's EBP
    mov     ebp, esp    ; EBP = 0019FEF0h -> [ebp+4] = ret, [ebp+8] = 1, [ebp+0Ch] = 2
    ...
    pop     ebp         ; ESP = 0019FEF4h
    ret                 ; EIP = [0019FEF4], ESP = 0019FEF8h
    add     esp, 8      ; (caller) ESP = 0019FF00h again
```

**If ESP isn't restored before `ret`**, for example when a value pushed in the body was never popped, `ret` pops that value instead of the return address and jumps to it. A stack overflow does the same thing on purpose: it replaces the value `ret` will pop.

### 2.8 Reading and setting EIP ★

There is no `mov eax, eip`. EIP is only changed implicitly, so you have to use those implicit changes.

**Reading EIP (GetPC, used in position-independent shellcode):**

```asm
; 1) call / pop
    call    next        ; pushes the address of 'next'
next:
    pop     eax         ; EAX = address of 'next'  (E8 00 00 00 00 contains NULL bytes)

; 2) NULL-free variant: jump forward, then call backward
    jmp     short get
back:
    pop     eax         ; EAX = address after the call
    ...
get:
    call    back        ; backward call -> negative rel32, no 00 bytes

; 3) FPU environment trick (used by some encoders)
    fldz                ; any x87 instruction records its own address
    fnstenv [esp-0Ch]   ; saved FPU instruction pointer lands at [esp]
    pop     eax         ; EAX = address of the fldz
```

**Setting EIP to an address:**

```asm
    mov     eax, 0AABBCCDDh
    jmp     eax                     ; 1) indirect jump

    mov     eax, 0AABBCCDDh
    call    eax                     ; 2) indirect call (also pushes a return address)

    push    0AABBCCDDh
    ret                             ; 3) push + ret  (the core idea behind ROP)
```

### 2.9 Callee-saved registers in prologue and epilogue ★

```asm
    push    ebp
    mov     ebp, esp
    sub     esp, 20h
    push    ebx                 ; this function uses EBX, ESI, EDI,
    push    esi                 ; so it must preserve them for the caller
    push    edi
    ...
    pop     edi                 ; popped in REVERSE order
    pop     esi
    pop     ebx
    mov     esp, ebp
    pop     ebp
    ret
```

The saved registers sit **below** the locals (lower addresses) under `/Od` MSVC, but between the locals and saved EBP in some optimized frames. Check the real layout in the debugger before counting overflow offsets.

---

## 3. Variables and memory access

### 3.1 Locals, arguments, globals

```c
int g = 5;              // .data
static int s;           // .bss/.data, not exported
void f(int a) {
    int x = a;
    g = x;
    s++;
}
```

```asm
    mov     eax, [ebp+8]            ; a
    mov     [ebp-4], eax            ; x = a
    mov     ecx, [ebp-4]
    mov     dword_403000, ecx       ; g (absolute address -> global)
    mov     edx, dword_403004
    add     edx, 1
    mov     dword_403004, edx       ; s++
```

An absolute address in `.data` or `.bss` means a global or static variable. An `[ebp±N]` address is a local or argument.

### 3.2 Initialized local values

```c
int a = 0;      // mov dword ptr [ebp-4], 0
int b = -1;     // mov dword ptr [ebp-8], 0FFFFFFFFh
char c = 'A';   // mov byte ptr [ebp-9], 41h
```

Optimized code uses `xor eax, eax` for 0 and `or eax, 0FFFFFFFFh` for -1.

### 3.3 Sign vs zero extension (spots signed/unsigned types)

```c
char c;           int i = c;    // movsx eax, byte ptr [ebp-1]
unsigned char u;  int j = u;    // movzx eax, byte ptr [ebp-2]
short s;          int k = s;    // movsx eax, word ptr [ebp-4]
unsigned short w; int m = w;    // movzx eax, word ptr [ebp-6]
```

This matters for bug hunting: `movsx` on a length byte is the signed-char length bug from the overflow catalog.

### 3.4 Pointers

```c
int  x = 7;
int *p = &x;      // lea eax, [ebp-4]   ; mov [ebp-8], eax
int  y = *p;      // mov ecx, [ebp-8]   ; mov edx, [ecx]   ; mov [ebp-0Ch], edx
*p = 9;           // mov eax, [ebp-8]   ; mov dword ptr [eax], 9
int **pp = &p;    // lea ecx, [ebp-8]   ; mov [ebp-10h], ecx
**pp = 1;         // mov edx, [ebp-10h] ; mov eax, [edx] ; mov dword ptr [eax], 1
```

`lea` gives an address (`&`), and `mov reg, [reg]` dereferences it (`*`). Count the dereferences to recover the level of indirection.

### 3.5 String literals

```c
const char *s = "hello";       // mov dword ptr [ebp-4], offset aHello  (.rdata)
const wchar_t *w = L"hi";      // mov dword ptr [ebp-8], offset aHi     ; 'h',0,'i',0,0,0
char buf[] = "abc";            // mov eax, dword ptr ds:aAbc ; mov [ebp-8], eax  (copied onto the stack)
```

Short array initializers become a few `mov` instructions. Longer ones become `rep movsd` or a `memcpy`.


### 3.6 Addressing modes: `[base + index*scale + displacement]` ★

Any part can be missing. The scale can only be 1, 2, 4 or 8.

| Form | Example | Typical C |
|---|---|---|
| `[disp]` | `mov eax, [404010h]` | global variable |
| `[base]` | `mov eax, [ecx]` | `*p`, first struct field |
| `[base+disp]` | `mov eax, [ecx+1Ch]` | `p->field`, local `[ebp-8]`, arg `[ebp+8]` |
| `[base+index]` | `mov dl, [eax+ecx]` | `buf[i]` (bytes) |
| `[base+index*scale]` | `mov eax, [edi+esi*4]` | `arr[i]` (ints) |
| `[base+index*scale+disp]` | `mov eax, [ebp+esi*4-40h]` | local `int arr[]` at `ebp-40h` |
| `[index*scale+disp]` | `mov eax, [404000h+esi*4]` | global array or jump table |

`lea` uses the same syntax but **does not read memory**. It only computes the address, so `lea edi, [ebp-0C0h]` makes `EDI = EBP - 0xC0`.

### 3.7 Operand size and prefixes ★

```asm
C6 01 13                mov  byte ptr  [ecx], 13h       ; 1 byte
66 C7 01 13 00          mov  word ptr  [ecx], 13h       ; 66h prefix -> 16-bit
C7 01 13 00 00 00       mov  dword ptr [ecx], 13h       ; 4 bytes (default)
```

When the instruction has no register to imply the size, the `byte/word/dword ptr` keyword tells you the C type of the field being written.

### 3.8 One wide write can initialize several small fields ★

```c
struct hdr { uint8_t type; uint8_t flags; uint16_t len; };   // 4 bytes
h->type = 1;  h->flags = 0x80;  h->len = 0;
```

```asm
    mov     dword ptr [ecx], 8001h      ; bytes 01 80 00 00 (little-endian)
                                        ; -> type = 01, flags = 80h, len = 0000h
```

If a constant written to a struct looks odd, split it by the struct's field layout. Related size-optimized stores:

```asm
    and     dword ptr [ecx+1Ch], 0      ; p->field = 0   (4 bytes instead of 7 for mov)
    or      dword ptr [ecx+20h], 0FFFFFFFFh   ; p->field = -1
```

### 3.9 "count + array" structs: inline array vs pointer ★

```asm
; (a) array stored INSIDE the struct
lp: mov     eax, [edi+ebx*4+4]          ; base + 4 + i*4
    ...
    inc     ebx
    cmp     ebx, [edi]                  ; i < s->count
    jl      short lp
```

```c
struct s { DWORD count; DWORD items[ANYSIZE]; };   // items at +4
```

```asm
; (b) struct holds a POINTER to the array
lp: mov     eax, [edi+4]                ; load s->items (a pointer) ...
    mov     eax, [eax+ebx*4]            ; ... then index it
    ...
    inc     ebx
    cmp     ebx, [edi]
    jl      short lp
```

```c
struct s { DWORD count; DWORD *items; };          // pointer at +4
```

The difference is one extra dereference. `jl` tells you the index is signed.

---

## 4. Arithmetic

### 4.1 Basic operations

```c
c = a + b;   // mov eax,[a] ; add eax,[b] ; mov [c],eax
c = a - b;   // sub
c = a * b;   // imul eax, [b]          (signed and unsigned low 32 bits are identical)
c = -a;      // neg eax
c = ~a;      // not eax
c = a & b;   // and      c = a | b;   // or      c = a ^ b;   // xor
c = a << 3;  // shl eax, 3
c = a >> 3;  // sar eax, 3   (signed int: arithmetic shift)
c = u >> 3;  // shr eax, 3   (unsigned: logical shift)  <- reveals signedness
a++;         // add dword ptr [a], 1   (inc at /O2)
```

### 4.2 Division and modulo by a variable

```c
int q = a / b;  int r = a % b;          // signed
```

```asm
    mov     eax, [ebp+8]        ; a
    cdq                         ; sign-extend EAX into EDX:EAX
    idiv    dword ptr [ebp+0Ch] ; EAX = quotient, EDX = remainder
```

```c
unsigned q = a / b;                     // unsigned
```

```asm
    mov     eax, [ebp+8]
    xor     edx, edx            ; zero-extend
    div     dword ptr [ebp+0Ch]
```

`cdq` + `idiv` means signed; `xor edx, edx` + `div` means unsigned.

### 4.3 Multiplication by constants (optimized `lea` tricks)

The following were verified with real compiler output:

```c
x * 9        // lea eax, [eax+eax*8]
x * 5 + 3    // lea eax, [eax+eax*4+3]
x * 3        // lea eax, [eax+eax*2]
x * 10       // lea eax, [eax+eax*4] ; add eax, eax
x * 2        // add eax, eax           (or shl eax, 1)
```

### 4.4 Division by constants: "magic numbers"

The compiler replaces division with multiplication by a precomputed reciprocal. Recognizing the constant tells you the divisor.

```c
unsigned u10(unsigned x) { return x / 10; }
```

```asm
    mov     eax, 0CCCCCCCDh
    mul     dword ptr [esp+4]   ; EDX = high 32 bits of x * magic
    mov     eax, edx
    shr     eax, 3              ; x / 10
```

```c
int s7(int x) { return x / 7; }
```

```asm
    mov     ecx, [esp+4]
    mov     eax, 92492493h
    imul    ecx
    lea     eax, [edx+ecx]
    sar     ecx, 1Fh            ; ECX = sign mask (0 or -1)
    sar     eax, 2
    sub     eax, ecx            ; corrects rounding toward zero for negatives
```

Common magic numbers:

| Divisor | Unsigned magic | Signed magic |
|---|---|---|
| 3 | `0AAAAAAABh` (shr 1) | `55555556h` |
| 5 | `0CCCCCCCDh` (shr 2) | `66666667h` (sar 1) |
| 7 | `24924925h` (+ fixup) | `92492493h` |
| 10 | `0CCCCCCCDh` (shr 3) | `66666667h` (sar 2) |
| 100 | `51EB851Fh` (shr 5) | `51EB851Fh` (sar 5) |
| 1000 | `10624DD3h` (shr 6) | `10624DD3h` (sar 6) |

To recover the divisor yourself: `divisor ≈ 2^(32+shift) / magic`. IDA and Ghidra decompilers do this automatically.

### 4.5 Signed division and modulo by a power of 2

The fixup makes negative numbers round toward zero.

```c
int d8(int x) { return x / 8; }
```

```asm
    mov     edx, [esp+4]
    test    edx, edx
    lea     eax, [edx+7]        ; bias by divisor-1 if negative
    cmovns  eax, edx
    sar     eax, 3
```

MSVC often writes the same thing as `cdq` + `and edx, 7` + `add eax, edx` + `sar eax, 3`.

```c
int m8(int x) { return x % 8; }
```

```asm
    mov     eax, [esp+4]
    cdq
    shr     edx, 1Dh            ; 7 if negative, else 0
    add     eax, edx
    and     eax, 7
    sub     eax, edx
```

For unsigned values it's just `shr eax, 3` and `and eax, 7`.

### 4.6 `long long` / `__int64` arithmetic in 32-bit x86 code

```c
long long add64(long long a, long long b) { return a + b; }
```

```asm
    mov     eax, [ebp+8]        ; a.lo
    mov     edx, [ebp+0Ch]      ; a.hi
    add     eax, [ebp+10h]      ; + b.lo
    adc     edx, [ebp+14h]      ; + b.hi + carry
```

A 32-bit CPU has no 64-bit registers, so these 8-byte integer values are split across a register pair (EDX:EAX). Subtraction is `sub` + `sbb`. Multiplication, division and shifts of these values call CRT helpers:

| Operation | MSVC helper | GCC helper |
|---|---|---|
| `a * b` | `__allmul` (inlined as a single `mul` when both high halves are known to be 0) | inline (3× `mul`/`imul`) |
| `a / b` signed / unsigned | `__alldiv` / `__aulldiv` | `___divdi3` / `___udivdi3` |
| `a % b` | `__allrem` / `__aullrem` | `___moddi3` / `___umoddi3` |
| `a << n`, `a >> n` | `__allshl`, `__allshr`, `__aullshr` (or `shld`/`shrd` inline) | inline |

A sequence like `shld edx, eax, cl` followed by `shl eax, cl` is a `long long` left shift on the EDX:EAX pair.

### 4.7 Branchless idioms (optimized)

These were verified with real compiler output:

```c
return x == 0;            // xor eax,eax ; test edx,edx ; sete al
return x < 0 ? -x : x;    // mov eax,edx ; neg eax ; cmovs eax,edx     (abs)
return x ? 5 : 9;         // cmp [x],1 ; sbb eax,eax ; and eax,4 ; add eax,5
return a < b ? -1 : 0;    // (unsigned) cmp a,b ; sbb eax,eax
```

In older MSVC code, abs appears as `cdq` + `xor eax, edx` + `sub eax, edx`.

`sbb reg, reg` turns the carry flag into 0 or -1. It almost always comes from an unsigned comparison or a `x != 0` test.


### 4.8 MUL / IMUL / DIV / IDIV operand forms ★

| Instruction | Operation |
|---|---|
| `mul r/m8` | `AX = AL * src` |
| `mul r/m16` | `DX:AX = AX * src` |
| `mul r/m32` | `EDX:EAX = EAX * src` (unsigned) |
| `imul r/m32` | `EDX:EAX = EAX * src` (signed, one operand) |
| `imul r32, r/m32` | `r32 = r32 * src` (low 32 bits only) |
| `imul r32, r/m32, imm` | `r32 = src * imm` |
| `div r/m8` | `AX / src` gives quotient in `AL`, remainder in `AH` |
| `div r/m16` | `DX:AX / src` gives `AX`, remainder in `DX` |
| `div r/m32` | `EDX:EAX / src` gives `EAX`, remainder in `EDX` (unsigned) |
| `idiv …` | same shapes, signed (needs `cdq`/`cwd`/`cbw` first) |

```asm
    mov     ax, 0Bh
    mov     cl, 3
    div     cl              ; AL = 3, AH = 2   (11 = 3*3 + 2)
```

A divide by zero, or a quotient too large for the destination, raises a **#DE (divide error)**. Windows reports division by zero as `STATUS_INTEGER_DIVIDE_BY_ZERO` (`0C0000094h`) and an oversized quotient (for example `INT_MIN / -1`) as `STATUS_INTEGER_OVERFLOW` (`0C0000095h`). Both go through SEH like any other exception.

### 4.9 Rotates, byte swaps and bit instructions ★

| Instruction | Meaning | Where you see it |
|---|---|---|
| `rol r, n` / `ror r, n` | rotate left/right (bits wrap around) | hashes, crypto, **API hashing in shellcode** |
| `rcl` / `rcr` | rotate through CF | multi-word shifts |
| `shld` / `shrd` | double-precision shift | `long long` shifts |
| `bswap r32` | reverse the byte order | `htonl`/`ntohl` inlined |
| `xchg al, ah` / `rol ax, 8` | swap 2 bytes | `htons`/`ntohs` inlined |
| `bt` / `bts` / `btr` / `btc` | test / set / reset / complement bit (into CF) | flag sets, bitmaps |
| `bsf` / `bsr` | index of lowest / highest set bit | |
| `inc` / `dec` | ±1, **does not change CF** | counters |

A ROR-13 API-name hash loop, the technique used by Metasploit-style shellcode (real implementations differ in details, such as also hashing the terminating NUL or the module name):

```asm
    xor     eax, eax            ; upper bits of EAX stay 0 (lodsb only writes AL)
    xor     edx, edx            ; hash = 0
lp: lodsb                       ; AL = next char of the export name
    test    al, al
    jz      short done
    ror     edx, 0Dh            ; hash = ror(hash, 13) + c
    add     edx, eax
    jmp     short lp
done:
    cmp     edx, [esp+hash]     ; compare with the wanted function's hash
```

An unexplained `ror reg, 0Dh` in a loop over strings is API hashing.

---

## 5. Conditionals

### 5.1 Jump selection reveals signedness

The jump instruction is usually the **inverse** of the C condition, because the compiler jumps *around* the if-body.

| C condition | Signed jump to *skip* the body | Unsigned jump to *skip* the body |
|---|---|---|
| `a == b` | `jnz` / `jne` | same |
| `a != b` | `jz` / `je` | same |
| `a < b` | `jge` | `jae` / `jnb` |
| `a <= b` | `jg` | `ja` |
| `a > b` | `jle` | `jbe` |
| `a >= b` | `jl` | `jb` |

`jl`/`jg`/`jle`/`jge` mean signed comparisons, and `jb`/`ja`/`jbe`/`jae` mean unsigned. This is exactly how you spot the **signed length check** bug (`if (len < 64)` compiled with `jge`).

### 5.2 if

```c
if (a > 10)
    x = 1;
```

```asm
    cmp     dword ptr [ebp+8], 0Ah
    jle     short skip          ; inverse condition
    mov     dword ptr [ebp-4], 1
skip:
```

### 5.3 if / else

```c
if (a == 0) x = 1; else x = 2;
```

```asm
    cmp     dword ptr [ebp+8], 0
    jnz     short else_
    mov     dword ptr [ebp-4], 1
    jmp     short end_          ; jump over the else-block
else_:
    mov     dword ptr [ebp-4], 2
end_:
```

A forward `jmp` at the end of a block followed by a label means an else branch is present.

### 5.4 if / else if / else chain

```c
if (a == 1) f1(); else if (a == 2) f2(); else f3();
```

```asm
    cmp     dword ptr [ebp+8], 1
    jnz     short L2
    call    _f1
    jmp     short Lend
L2: cmp     dword ptr [ebp+8], 2
    jnz     short L3
    call    _f2
    jmp     short Lend
L3: call    _f3
Lend:
```

### 5.5 `&&` (short-circuit AND)

```c
if (a > 0 && b > 0) x = 1;
```

```asm
    cmp     dword ptr [ebp+8], 0
    jle     short skip          ; first fails -> skip everything
    cmp     dword ptr [ebp+0Ch], 0
    jle     short skip
    mov     dword ptr [ebp-4], 1
skip:
```

Several jumps that all go to the same "skip" target mean `&&`.

### 5.6 `||` (short-circuit OR)

```c
if (a > 0 || b > 0) x = 1;
```

```asm
    cmp     dword ptr [ebp+8], 0
    jg      short body          ; first true -> go straight to the body (non-inverted jump)
    cmp     dword ptr [ebp+0Ch], 0
    jle     short skip
body:
    mov     dword ptr [ebp-4], 1
skip:
```

A non-inverted jump into the body means `||`.

### 5.7 NULL / boolean tests

```c
if (p) ...       // cmp dword ptr [ebp-4], 0 ; jz skip     (/O2: test eax,eax ; jz)
if (!p) ...      // ... jnz skip
if (flags & 4)   // mov eax,[flags] ; and eax,4 ; jz skip    (/O2: test al,4 ; jz)
```

`test reg, reg` is `cmp reg, 0` without storing a result. `test reg, imm` checks a bit.

### 5.8 Ternary and boolean results

```c
x = (a > b) ? a : b;            // /Od: branches like if/else.  /O2: cmp ; cmovl/cmovg
int eq = (a == b);              // cmp ; sete al ; movzx eax, al
```

### 5.9 Comparison against a range (optimized bounds check)

```c
if (c >= 'a' && c <= 'z')
```

```asm
    lea     eax, [ecx-61h]      ; c - 'a'
    cmp     eax, 19h            ; <= 25 ?
    ja      short not_lower     ; ONE unsigned compare replaces two signed ones
```

The pattern `sub`/`lea` followed by an unsigned `cmp` + `ja` is a range check. The same trick produces switch bounds checks.

### 5.10 Nested if

```c
if (a > 0) {
    if (b > 0) x = 1;
    else       x = 2;
}
```

```asm
    cmp     dword ptr [ebp+8], 0
    jle     short end_          ; outer test skips the whole inner block
    cmp     dword ptr [ebp+0Ch], 0
    jle     short inner_else
    mov     dword ptr [ebp-4], 1
    jmp     short end_
inner_else:
    mov     dword ptr [ebp-4], 2
end_:
```

An outer jump whose target is *past* an inner if/else (a jump that skips several blocks) means nesting. Note that `if (a > 0 && b > 0)` without an `else` produces exactly the same code as a nested if without an `else`.

### 5.11 Mixed `&&` / `||`

```c
if (a == 1 && (b == 2 || c == 3)) x = 1;
```

```asm
    cmp     dword ptr [ebp+8], 1
    jnz     short skip          ; && part fails -> skip
    cmp     dword ptr [ebp+0Ch], 2
    jz      short body          ; || first part true -> body
    cmp     dword ptr [ebp+10h], 3
    jnz     short skip          ; || second part false -> skip
body:
    mov     dword ptr [ebp-4], 1
skip:
```

To recover the expression, look at the targets. Jumps to `skip` are conditions that must hold (`&&`). A jump straight to `body` is an alternative (`||`).

### 5.12 Negated compound conditions (De Morgan)

```c
if (!(a > 0 && b > 0)) x = 1;       // same as: if (a <= 0 || b <= 0)
```

```asm
    cmp     dword ptr [ebp+8], 0
    jle     short body          ; a <= 0 -> body
    cmp     dword ptr [ebp+0Ch], 0
    jg      short skip
body:
    mov     dword ptr [ebp-4], 1
skip:
```

The decompiler shows whichever form is simpler. Both are correct.

### 5.13 Sign tests

```c
if (x < 0)   ...    // test eax, eax ; jns skip      (or: cmp eax, 0 ; jge skip)
if (x >= 0)  ...    // test eax, eax ; js  skip
return x < 0;       // shr eax, 1Fh        (verified: sign bit -> 0/1)
```

`js`/`jns` test only the sign flag and are commonly used against 0.

### 5.14 Bit and flag tests

```c
if (f & 4)                 // test byte ptr [f], 4 ; jz skip
if (f & 0x80000000)        // test eax, eax ; jns skip   (top bit = sign)
if ((f & 6) == 6)          // and eax, 6 ; cmp eax, 6 ; jnz skip
                           //   /O2 variant (verified): not eax ; test al, 6 ; sete al
if ((f >> n) & 1)          // shr eax, cl ; and eax, 1     or     bt eax, ecx ; jnb skip
if (f & (A | B))           // test eax, A|B ; jz skip     ("any of")
```

`bt reg, reg` copies the tested bit into the carry flag, so `jb`/`jc` means set and `jnb`/`jnc` means clear.

### 5.15 Testing against a set of constants: bitmask (optimized)

```c
int isvowel(char c) { return c=='a'||c=='e'||c=='i'||c=='o'||c=='u'; }
```

```asm
    movzx   eax, byte ptr [esp+4]
    lea     ecx, [eax-61h]      ; c - 'a'
    xor     eax, eax
    cmp     cl, 14h             ; outside 'a'..'u' ?
    ja      short ret_
    mov     eax, 104111h        ; bits 0,4,8,14,20 = a,e,i,o,u
    shr     eax, cl
    and     eax, 1              ; (mask >> (c-'a')) & 1
ret_:
```

The same trick applies to `x==1||x==3||x==5||x==7`, which becomes `cmp ecx, 7 ; ja` followed by `mov eax, 0AAh ; shr eax, cl ; and eax, 1`. MSVC often uses `bt` here instead of `shr`. To decode the constant, list its set bits and add the base offset. (Both listings were verified with real compiler output.)

### 5.16 Byte and char comparisons

```c
if (buf[0] == 'A')     // cmp byte ptr [ebp-40h], 41h ; jnz skip
if (c == '\r' || c == '\n')
```

```asm
    movsx   eax, byte ptr [ebp-1]
    cmp     eax, 0Dh
    jz      short body
    movsx   ecx, byte ptr [ebp-1]
    cmp     ecx, 0Ah
    jnz     short skip
body:
```

Byte comparisons against `0`, `0Ah`, `0Dh`, `20h`, `3Bh` (`;`) and `3Ah` (`:`) inside loops are parsing delimiters. Delimiters a parser treats specially are also bytes your payload can't freely contain, so note them as bad-char candidates.

### 5.17 Conditions on function results

```c
if (!strcmp(cmd, "HELP"))      ...
if (strncmp(buf, "TRUN ", 5) == 0) ...
if (recv(s, buf, n, 0) <= 0)   ...
if ((h = CreateFileA(...)) == INVALID_HANDLE_VALUE) ...
```

```asm
    push    offset aHelp
    push    [ebp-cmd]
    call    _strcmp
    add     esp, 8
    test    eax, eax            ; strcmp result == 0 ?
    jnz     short not_help

    push    5
    push    offset aTrun        ; "TRUN "
    lea     eax, [ebp-1000h]
    push    eax
    call    _strncmp
    add     esp, 0Ch
    test    eax, eax
    jnz     short next_cmd      ; <- typical command dispatcher

    call    ds:__imp__recv@16
    cmp     eax, 0
    jle     short closed        ; signed: also catches SOCKET_ERROR (-1)

    call    ds:__imp__CreateFileA@28
    mov     [ebp-h], eax
    cmp     dword ptr [ebp-h], 0FFFFFFFFh   ; INVALID_HANDLE_VALUE
    jz      short fail
```

The constant compared against tells you what the check is. `0` means success or NULL, `-1` means an invalid handle or `SOCKET_ERROR`, and `0B7h` means `ERROR_ALREADY_EXISTS` (from `GetLastError`).

### 5.18 Assignment inside a condition

```c
if ((p = strchr(s, ':')) != NULL) *p = 0;
```

```asm
    push    3Ah
    push    [ebp-s]
    call    _strchr
    add     esp, 8
    mov     [ebp-p], eax        ; store first...
    cmp     dword ptr [ebp-p], 0 ; ...then test
    jz      short skip
    mov     ecx, [ebp-p]
    mov     byte ptr [ecx], 0
skip:
```

### 5.19 Guard clauses / early returns

```c
int f(char *s, int n) {
    if (!s)      return -1;
    if (n > 512) return -2;
    ...
    return 0;
}
```

```asm
    cmp     dword ptr [ebp+8], 0
    jnz     short chk2
    or      eax, 0FFFFFFFFh     ; return -1
    jmp     short epilogue      ; all early returns jump to ONE shared epilogue
chk2:
    cmp     dword ptr [ebp+0Ch], 200h
    jle     short body
    mov     eax, 0FFFFFFFEh     ; return -2
    jmp     short epilogue
body:
    ...
    xor     eax, eax
epilogue:
    mov     esp, ebp
    pop     ebp
    ret
```

Several `mov eax, CONST ; jmp epilogue` blocks are early returns, and the constants are error codes. These checks are what an exploit input has to pass to reach the vulnerable code.

### 5.20 `goto cleanup` pattern

```c
if (!(a = open_a())) goto out;
if (!(b = open_b())) goto close_a;
...
close_a: close(a);
out:     return rc;
```

You'll see forward jumps to a ladder of cleanup blocks at the end of the function, each one falling through to the next. In C++ code, the destructor calls that run on each exit path look similar.

### 5.21 Security-relevant checks: signed vs unsigned side by side

```c
int  len;      if (len > 64) return;    // cmp eax, 40h ; jg  ret_   <- negative len passes!
unsigned len;  if (len > 64) return;    // cmp eax, 40h ; ja  ret_   <- correct
size_t n;      if (a + b < a) fail;     // add eax, ecx ; jb fail    (unsigned overflow check)
                                        //   /O2 (verified): add eax,[b] ; sbb eax,eax
int x;         if (x + 1 < x)  fail;    // /Od: add eax,1 ; cmp eax,[x] ; jge ok — at /O2 often removed
                                        //   entirely, because signed overflow is undefined behavior
```

When auditing a bounds check, look at **which jump** is used. `jg`/`jl`/`jge`/`jle` on a length means a signed compare, which a negative value bypasses.

### 5.22 Pointer comparisons

```c
if (p < end)        // cmp eax, ecx ; jnb done        (pointers compare unsigned)
if (p == NULL)      // test eax, eax ; jnz notnull
```

### 5.23 `long long` comparisons in 32-bit x86 code

```c
if (a < b)   // long long
```

```asm
    mov     eax, [ebp+0Ch]      ; a.hi
    cmp     eax, [ebp+14h]      ; b.hi
    jg      short skip          ; high parts decide first (signed)
    jl      short body
    mov     ecx, [ebp+8]        ; a.lo
    cmp     ecx, [ebp+10h]      ; b.lo
    jnb     short skip          ; low parts compared UNSIGNED
body:
```

An optimized version (verified) uses one subtract-with-borrow: `cmp lo, lo` followed by `sbb hi, hi`, then `setl` or `jl`.

### 5.24 Floating-point conditions

The x87 form is what you'll see in older MSVC builds:

```c
if (a < b)  ...       // a, b are double
```

```asm
    fld     qword ptr [ebp-8]   ; a
    fcomp   qword ptr [ebp-10h] ; compare with b, pop
    fnstsw  ax                  ; FPU status word -> AX
    test    ah, 5               ; C0 | C2
    jp      short skip          ; PF trick: odd bit count -> a < b
```

| C | x87 MSVC test |
|---|---|
| `a < b` | `test ah, 5 ; jp skip` |
| `a == b` | `test ah, 44h ; jp skip` |
| `a > b` | usually operands swapped and the `a < b` form reused, or `test ah, 41h ; jnz skip` |

Modern P6+ builds use `fcomip st, st(1)` followed by `jbe`/`jae` style jumps. SSE uses `comiss`/`comisd` (or `ucomisd`) followed by `jbe`/`jae`/`jp` (`jp` catches NaN).

### 5.25 Conditional moves and setcc (branchless conditions)

| Instruction | Condition |
|---|---|
| `sete`/`cmove` | `==` |
| `setne`/`cmovne` | `!=` |
| `setl`/`cmovl`, `setg`/`cmovg` | signed `<`, `>` |
| `setb`/`cmovb`, `seta`/`cmova` | unsigned `<`, `>` |
| `sets`/`cmovs` | `< 0` |

```c
bool ok = (a > 5) && c;       // /O2 may compute both and combine them
```

```asm
    cmp     dword ptr [a], 5
    setg    al
    test    ecx, ecx
    setne   dl
    and     al, dl              ; bool AND without branches
```

Both sides can be evaluated without branches only when the right side has no side effects. Function calls keep real short-circuit jumps.

### 5.26 Recognizing conditions in the CFG view

| Graph shape (IDA graph view) | C construct |
|---|---|
| Diamond (split → two blocks → join) | if/else, ternary |
| Triangle (split → one block → join) | if without else |
| Several splits converging on one "false" block | `&&` chain |
| Several splits converging on one "true" block | `\|\|` chain |
| Block with an edge back up to an earlier block | loop |
| One block fanning out to many | switch (jump table) |
| Many blocks converging on one exit block | early returns / shared epilogue |

---

## 6. Loops

### 6.1 for (unoptimized shape)

```c
for (int i = 0; i < n; i++)
    sum += arr[i];
```

```asm
    mov     dword ptr [ebp-8], 0        ; i = 0
    jmp     short cond
incr:
    mov     eax, [ebp-8]
    add     eax, 1
    mov     [ebp-8], eax                ; i++
cond:
    mov     ecx, [ebp-8]
    cmp     ecx, [ebp+0Ch]              ; i < n ?
    jge     short done
    mov     edx, [ebp-8]
    mov     eax, [ebp+8]                ; arr
    mov     ecx, [eax+edx*4]            ; arr[i]  (scale 4 = int)
    add     ecx, [ebp-4]
    mov     [ebp-4], ecx                ; sum += ...
    jmp     short incr                  ; backward jump = loop
done:
```

The MSVC `/Od` signature is init → `jmp` to the condition → increment block placed *before* the condition.

### 6.2 while

```c
while (*s) s++;
```

```asm
top:
    mov     eax, [ebp+8]
    movsx   ecx, byte ptr [eax]
    test    ecx, ecx
    jz      short done
    mov     edx, [ebp+8]
    add     edx, 1
    mov     [ebp+8], edx
    jmp     short top
done:
```

### 6.3 do-while

```c
do { x--; } while (x > 0);
```

```asm
top:
    mov     eax, [ebp-4]
    sub     eax, 1
    mov     [ebp-4], eax
    cmp     dword ptr [ebp-4], 0
    jg      short top           ; conditional BACKWARD jump at the bottom
```

### 6.4 Optimized ("rotated") loop

At `/O2`, most loops look like a do-while with a guard in front:

```asm
    test    ecx, ecx            ; if (n <= 0) skip   <- guard
    jle     short done
    xor     eax, eax            ; i = 0
top:
    add     edx, [esi+eax*4]    ; sum += arr[i]
    inc     eax
    cmp     eax, ecx
    jl      short top           ; single compare at the bottom
done:
```

The optimizer may also count down (`dec ecx` / `jnz`), turn the index into a walking pointer (`add esi, 4`), or unroll the body 2–4×.

### 6.5 break / continue

```c
for (i = 0; i < n; i++) {
    if (a[i] == 0) continue;
    if (a[i] < 0)  break;
    f(a[i]);
}
```

`continue` is a jump to the increment block, and `break` is a jump to the label after the loop. Both are forward jumps from inside the body.

### 6.6 Nested loops (2D iteration)

```c
for (i = 0; i < R; i++)
    for (j = 0; j < C; j++)
        m[i][j] = 0;
```

The inner loop's counter is reset (`mov [j], 0`) inside the outer loop's body. The address is computed as `base + (i*C + j)*elemsize`, typically with `imul eax, C` followed by `[base + eax*4]`.

### 6.7 Inlined memory and string operations (very common)

```c
memset(buf, 0, 64);          // /O2 or intrinsic
```

```asm
    xor     eax, eax
    mov     ecx, 10h            ; 64 / 4 dwords
    lea     edi, [ebp-40h]
    rep stosd
```

```c
memcpy(dst, src, 40);
```

```asm
    mov     ecx, 0Ah            ; 40 / 4
    mov     esi, [src]
    mov     edi, [dst]
    rep movsd                   ; leftovers via movsw/movsb if size isn't a multiple of 4
```

```c
n = strlen(s);               // classic inline form (older MSVC / size optimization)
```

```asm
    mov     edi, [s]
    or      ecx, 0FFFFFFFFh
    xor     eax, eax
    repne scasb                 ; scan for 0
    not     ecx
    dec     ecx                 ; ECX = length
```

The newer MSVC inline strlen looks like this:

```asm
    lea     edx, [eax+1]
lp: mov     cl, [eax]
    inc     eax
    test    cl, cl
    jnz     short lp
    sub     eax, edx            ; length
```

```c
strcpy(dst, src);            // inline byte loop
```

```asm
lp: mov     cl, [eax]           ; read src
    mov     [edx], cl           ; write dst  (no bounds -> overflow!)
    inc     eax
    inc     edx
    test    cl, cl
    jnz     short lp
```

An inlined `strcpy` won't appear in the import table, so look for this read-a-byte, write-a-byte, test-for-zero loop shape.

```c
if (!strcmp(a, "ADMIN"))     // inline compare: dword compares or a byte loop + sbb/or tricks
```

```asm
lp: mov     dl, [eax]
    cmp     dl, [ecx]
    jnz     short diff
    test    dl, dl
    jz      short equal
    ...
diff:
    sbb     eax, eax
    or      eax, 1              ; result -1 / 1
```

`repe cmpsb` / `repe cmpsd` is a `memcmp`.


### 6.8 The string-instruction family ★

| Instruction | Reads | Writes | Then |
|---|---|---|---|
| `movsb/w/d` | `[ESI]` | `[EDI]` | ESI, EDI ± size |
| `stosb/w/d` | `AL/AX/EAX` | `[EDI]` | EDI ± size |
| `lodsb/w/d` | `[ESI]` | `AL/AX/EAX` | ESI ± size |
| `scasb/w/d` | compares `AL/AX/EAX` with `[EDI]` | flags | EDI ± size |
| `cmpsb/w/d` | compares `[ESI]` with `[EDI]` | flags | ESI, EDI ± size |

The direction is set by **DF**. When DF=0 (after `cld`, the normal state) the pointers **increment**. When DF=1 (after `std`) they decrement, which is used rarely, for example for overlapping `memmove` copies.

| Prefix | Repeats while |
|---|---|
| `rep` | `ECX != 0` (decrementing ECX each time) |
| `repe` / `repz` | `ECX != 0` and ZF=1 (`memcmp`) |
| `repne` / `repnz` | `ECX != 0` and ZF=0 (`strlen`, `memchr`) |

**A fixed-size struct copy, unrolled:**

```asm
    mov     esi, offset g_Guid      ; source: a 16-byte global
    lea     edi, [ebp-20h]          ; destination: a local
    movsd
    movsd
    movsd
    movsd                           ; 4 x 4 = 16 bytes -> struct/GUID copy
```

**Odd sizes mix widths:**

```asm
    lea     esi, [eax+30h]
    lea     edi, [ebx+30h]          ; same offset in two pointers -> same struct type
    movsd
    movsd                           ; 8
    movsw                           ; +2
    movsb                           ; +1 = 11 bytes: memcpy(&b->f, &a->f, 11)
```

**`lods` / `stos` transform loop (an XOR decoder stub):**

```asm
    mov     esi, offset enc         ; source
    mov     edi, esi                ; decode in place
    mov     ecx, 1F4h               ; length
lp: lodsb
    xor     al, 0AAh
    stosb
    loop    lp
```

The shape `lods → arithmetic → stos → loop` is a decoder, encoder or simple cipher.

### 6.9 `LOOP`, `JECXZ` and the `push imm / pop reg` idiom ★

```asm
    push    9                       ; 6A 09
    pop     ecx                     ; 59      -> ECX = 9 in 3 bytes (vs 5 for mov ecx, 9)
    jecxz   skip                    ; don't enter the loop if the count is 0
top:
    ...
    loop    top                     ; dec ecx ; jnz top  (LOOP leaves the flags alone)
skip:
```

Compilers rarely emit `loop` today because it's slow, so seeing it suggests hand-written assembly, shellcode, or a size-optimized build.

---

## 7. switch statements

### 7.1 Few or sparse cases: compare chain

```c
switch (cmd) { case 1: a(); break; case 7: b(); break; default: c(); }
```

```asm
    mov     eax, [ebp+8]
    mov     [ebp-4], eax        ; /Od copies the switch value to a temp
    cmp     dword ptr [ebp-4], 1
    jz      short case1
    cmp     dword ptr [ebp-4], 7
    jz      short case7
    jmp     short default_
```

### 7.2 Dense cases: jump table

```c
switch (x) { case 0: ... case 1: ... case 2: ... case 3: ... case 4: ... default: ... }
```

```asm
    mov     eax, [ebp+8]
    cmp     eax, 4              ; unsigned bounds check (also catches negatives)
    ja      default_
    jmp     ds:jpt_401050[eax*4]   ; table of code addresses
jpt_401050 dd offset case0, offset case1, offset case2, offset case3, offset case4
```

If cases start at N rather than 0, there is a `sub eax, N` (or `add eax, -N`) before the bounds check.

### 7.3 Two-level table (MSVC, cases spread over a range with gaps)

```asm
    movzx   eax, ds:byte_401100[ecx]   ; byte index table: value -> case number
    jmp     ds:off_4010F0[eax*4]       ; jump table: case number -> code
```

### 7.4 Large sparse switch: binary search tree

```asm
    cmp     eax, 3E8h
    jg      short upper_half
    jz      short case_1000
    cmp     eax, 64h
    ...
```

A switch can also be turned into a value lookup (no jumps), as in this verified example where `switch` returns `10, 21, 32, …`:

```asm
    cmp     eax, 5
    ja      L_default
    lea     edx, [eax+eax*4]
    lea     edx, [eax+10+edx*2]  ; computed result: 11*x + 10
```

Protocol command dispatchers (e.g. `TRUN`, `GMON` in Vulnserver) are usually `strncmp` chains, not switches. Check each branch target for a sink.


### 7.5 switch as a subtract/decrement chain ★

```c
switch (op) { case 1: a(); break; case 2: b(); break; case 3: c(); break; case 10: d(); break; }
```

```asm
    mov     eax, [ebp+8]
    dec     eax
    jz      short case1             ; op == 1
    dec     eax
    jz      short case2             ; op == 2
    dec     eax
    jz      short case3             ; op == 3
    sub     eax, 7
    jz      short case10            ; op == 10  (3 + 7)
    jmp     short default_
```

To recover each case value, keep a running total of how much has been subtracted so far. The classic real-world example is `DllMain`'s `fdwReason`:

```asm
    mov     eax, [ebp+0Ch]          ; fdwReason
    dec     eax                     ; 1 = DLL_PROCESS_ATTACH
    jnz     short not_attach        ; everything except PROCESS_ATTACH skips the payload
```

---

## 8. Arrays

### 8.1 Indexing: the scale factor gives the element size

```c
int   c = cb[i];     // movsx eax, byte ptr [ecx+eax]        (char array, scale 1)
int   s = sb[i];     // movsx eax, word ptr [ecx+eax*2]      (short array, scale 2)
int   n = ib[i];     // mov   eax, [ecx+eax*4]               (scale 4)
double d = db[i];    // fld/movsd qword ptr [ecx+eax*8]      (scale 8)
```

For a local array, the base is a `lea` or a direct offset: `mov eax, [ebp+eax*4-40h]` means `int arr[16]` at `ebp-40h`.

### 8.2 Constant index

```c
arr[3] = 5;          // mov dword ptr [ebp-34h], 5    (= base -40h + 3*4)
```

With constant indexes the array "disappears" into plain offsets. Look for groups of evenly spaced stack slots.

### 8.3 Two-dimensional array

```c
int m[10][20];  m[i][j] = 1;
```

```asm
    mov     eax, [ebp-i]
    imul    eax, 50h            ; i * (20 * 4) = row size in bytes
    lea     ecx, [ebp+eax-328h] ; &m[i]
    mov     edx, [ebp-j]
    mov     dword ptr [ecx+edx*4], 1
```

### 8.4 Array of structs

```c
struct item { int id; int qty; char tag[4]; };   // 12 bytes
items[i].qty = 5;
```

```asm
    mov     eax, [ebp-i]
    imul    eax, 0Ch            ; i * sizeof(struct item)
    mov     dword ptr [ebp+eax-5Ch], 5   ; array at ebp-60h, +4 = qty
```

At `/O2`, `imul 0Ch` becomes `lea eax, [eax+eax*2]` followed by `[base+eax*4+4]`.

### 8.5 Pointer-walking loop (optimized array iteration)

```c
for (p = arr; p < arr + n; p++) *p = 0;
```

```asm
lp: mov     dword ptr [eax], 0
    add     eax, 4              ; p++ advances by sizeof(*p)
    cmp     eax, ecx
    jb      short lp            ; unsigned: pointer comparison
```

---

## 9. Structures and unions

### 9.1 Member access through a pointer

```c
struct conn { int sock; char name[32]; int (*handler)(char*); };
p->sock = s;  p->handler(p->name);
```

```asm
    mov     eax, [ebp+8]        ; p
    mov     ecx, [ebp+0Ch]
    mov     [eax], ecx          ; p->sock     (+0)
    mov     edx, [ebp+8]
    add     edx, 4              ; &p->name    (+4)
    push    edx
    mov     eax, [ebp+8]
    mov     ecx, [eax+24h]      ; p->handler  (+0x24 = 4 + 32)
    call    ecx
    add     esp, 4
```

A register used as a base with several small fixed offsets is a struct pointer. In IDA, press `T` on the operand to apply a struct type.

### 9.2 Padding and alignment

```c
struct s { char a; int b; short c; };   // a@0, pad 3, b@4, c@8, pad 2 -> sizeof 12
```

Gaps between offsets point to padding, which tells you the field types.

### 9.3 Struct passed by value

```c
void f(struct big b);   f(local);
```

```asm
    sub     esp, 28h            ; make room on the stack for the copy
    mov     ecx, 0Ah
    lea     esi, [ebp-30h]      ; local
    mov     edi, esp
    rep movsd                   ; copy struct onto the stack
    call    _f
    add     esp, 28h
```

Small structs (8 bytes or less) are usually just pushed as one or two dwords.

### 9.4 Struct returned by value (hidden pointer)

```c
struct big g(void);   struct big r = g();
```

```asm
    lea     eax, [ebp-60h]      ; temp
    push    eax                 ; hidden 1st argument
    call    _g
    add     esp, 4              ; g returns the same pointer in EAX
```

### 9.5 Bit fields

```c
struct { unsigned a:3, b:5; } s;
s.b = 7;
x = s.b;
```

```asm
    mov     eax, [ebp-4]
    and     eax, 0FFFFFF07h     ; clear bits 3..7
    or      eax, 38h            ; 7 << 3
    mov     [ebp-4], eax
    mov     ecx, [ebp-4]
    shr     ecx, 3
    and     ecx, 1Fh            ; read: shift + mask
```

### 9.6 Unions and type punning

The same stack slot is read with different widths or instructions, for example `mov` as an int and `fld` as a float, or `mov al` against `mov eax`.


---

## 10. Linked lists

All examples use this node unless stated otherwise:

```c
struct node {
    int          val;    // +0
    struct node *next;   // +4
};
```

The key pattern is **`reg = [reg + next_offset]` inside a loop, ending on a NULL test**. A register loaded from memory at an offset from *itself* is a linked-list walk.

### 10.1 Traversal / counting

```c
int count(struct node *p) {
    int n = 0;
    while (p) { n++; p = p->next; }
    return n;
}
```

`/Od` form:

```asm
    mov     dword ptr [ebp-4], 0        ; n = 0
top:
    cmp     dword ptr [ebp+8], 0        ; while (p)
    jz      short done
    mov     eax, [ebp-4]
    add     eax, 1
    mov     [ebp-4], eax                ; n++
    mov     ecx, [ebp+8]
    mov     edx, [ecx+4]                ; p->next
    mov     [ebp+8], edx                ; p = p->next
    jmp     short top
done:
```

`/O2` form (verified):

```asm
    mov     eax, [esp+4]
    xor     edx, edx
    test    eax, eax
    jz      short done
lp: mov     eax, [eax+4]                ; p = p->next   <- the signature instruction
    add     edx, 1
    test    eax, eax
    jnz     short lp
done:
    mov     eax, edx
```

### 10.2 Search by key

```c
struct node *find(struct node *p, int key) {
    for (; p; p = p->next)
        if (p->val == key) return p;
    return NULL;
}
```

`/O2` form (verified):

```asm
    mov     eax, [esp+4]                ; p
    mov     edx, [esp+8]                ; key
    test    eax, eax
    jnz     short cmp_
    jmp     short notfound
next_:
    mov     eax, [eax+4]                ; p = p->next
    test    eax, eax
    jz      short ret_                  ; end of list -> return NULL (EAX = 0)
cmp_:
    cmp     [eax], edx                  ; p->val == key ?
    jnz     short next_
ret_:
    ret                                 ; found: EAX = p
notfound:
    xor     eax, eax
    ret
```

With a string key, the `cmp` becomes `push [eax+name_off] ; push key ; call _strcmp ; test eax,eax`.

### 10.3 Insert at head

```c
struct node *push(struct node *head, int v) {
    struct node *n = malloc(sizeof *n);
    n->val  = v;
    n->next = head;
    return n;
}
```

```asm
    push    8                           ; sizeof(struct node)
    call    _malloc
    add     esp, 4
    mov     [ebp-4], eax                ; n
    mov     eax, [ebp-4]
    mov     ecx, [ebp+0Ch]
    mov     [eax], ecx                  ; n->val = v
    mov     edx, [ebp-4]
    mov     eax, [ebp+8]
    mov     [edx+4], eax                ; n->next = head
    mov     eax, [ebp-4]                ; return n
```

The allocation size (`push 8`) gives `sizeof(node)`. The stores at `[eax+N]` right after it give the field layout.

The version that updates a global head instead:

```asm
    mov     ecx, dword_404010           ; global head
    mov     [eax+4], ecx                ; n->next = head
    mov     dword_404010, eax           ; head = n
```

### 10.4 Append at tail

```c
void append(struct node **head, struct node *n) {
    struct node *p;
    n->next = NULL;
    if (!*head) { *head = n; return; }
    for (p = *head; p->next; p = p->next) ;
    p->next = n;
}
```

```asm
    mov     eax, [ebp+0Ch]
    mov     dword ptr [eax+4], 0        ; n->next = NULL
    mov     ecx, [ebp+8]
    cmp     dword ptr [ecx], 0          ; *head == NULL ?
    jnz     short walk
    mov     edx, [ebp+8]
    mov     eax, [ebp+0Ch]
    mov     [edx], eax                  ; *head = n   (write through a double pointer)
    jmp     short done
walk:
    mov     ecx, [ebp+8]
    mov     edx, [ecx]
    mov     [ebp-4], edx                ; p = *head
lp: mov     eax, [ebp-4]
    cmp     dword ptr [eax+4], 0        ; p->next != NULL ?
    jz      short found_tail
    mov     ecx, [ebp-4]
    mov     edx, [ecx+4]
    mov     [ebp-4], edx                ; p = p->next
    jmp     short lp
found_tail:
    mov     eax, [ebp-4]
    mov     ecx, [ebp+0Ch]
    mov     [eax+4], ecx                ; p->next = n
done:
```

`struct node **` shows up as **two** dereferences: `mov ecx,[ebp+8]` followed by `[ecx]`.

### 10.5 Delete a node (with a prev pointer)

```c
void remove_key(struct node **head, int key) {
    struct node *cur = *head, *prev = NULL;
    while (cur && cur->val != key) { prev = cur; cur = cur->next; }
    if (!cur) return;
    if (prev) prev->next = cur->next;
    else      *head      = cur->next;
    free(cur);
}
```

```asm
    ; loop: prev = cur ; cur = cur->next
    mov     eax, [ebp-cur]
    mov     [ebp-prev], eax
    mov     ecx, [ebp-cur]
    mov     edx, [ecx+4]
    mov     [ebp-cur], edx
    ...
    ; unlink
    cmp     dword ptr [ebp-prev], 0
    jz      short at_head
    mov     eax, [ebp-prev]
    mov     ecx, [ebp-cur]
    mov     edx, [ecx+4]
    mov     [eax+4], edx                ; prev->next = cur->next
    jmp     short do_free
at_head:
    mov     eax, [ebp+8]
    mov     ecx, [ebp-cur]
    mov     edx, [ecx+4]
    mov     [eax], edx                  ; *head = cur->next
do_free:
    push    [ebp-cur]
    call    _free
    add     esp, 4
```

The shape to recognize is two pointer variables moving in lockstep (`prev = cur` and then `cur = cur->next`).

### 10.6 Freeing a whole list (the `next` must be saved first)

```c
while (p) { struct node *nx = p->next; free(p); p = nx; }
```

```asm
lp: cmp     dword ptr [ebp-p], 0
    jz      short done
    mov     eax, [ebp-p]
    mov     ecx, [eax+4]
    mov     [ebp-nx], ecx               ; save next BEFORE free
    push    [ebp-p]
    call    _free
    add     esp, 4
    mov     edx, [ebp-nx]
    mov     [ebp-p], edx
    jmp     short lp
done:
```

If `p->next` is read **after** `call _free`, that is a use-after-free bug.

### 10.7 Reverse a list

```c
struct node *rev(struct node *p) {
    struct node *prev = NULL, *nx;
    while (p) { nx = p->next; p->next = prev; prev = p; p = nx; }
    return prev;
}
```

```asm
    xor     ecx, ecx                    ; prev = NULL
    test    eax, eax
    jz      short done
lp: mov     edx, [eax+4]                ; nx = p->next
    mov     [eax+4], ecx                ; p->next = prev
    mov     ecx, eax                    ; prev = p
    mov     eax, edx                    ; p = nx
    test    eax, eax
    jnz     short lp
done:
    mov     eax, ecx
```

### 10.8 Sorted insert

```c
while (*pp && (*pp)->val < n->val) pp = &(*pp)->next;
n->next = *pp;  *pp = n;
```

```asm
lp: mov     eax, [ebp-pp]
    cmp     dword ptr [eax], 0          ; *pp != NULL
    jz      short ins
    mov     ecx, [ebp-pp]
    mov     edx, [ecx]
    mov     eax, [edx]                  ; (*pp)->val
    mov     ecx, [ebp-n]
    cmp     eax, [ecx]                  ; < n->val ?
    jge     short ins
    mov     edx, [ebp-pp]
    mov     eax, [edx]
    add     eax, 4                      ; &(*pp)->next   <- address-of a field, no load
    mov     [ebp-pp], eax
    jmp     short lp
ins:
```

`add reg, 4` instead of `mov reg, [reg+4]` means taking the field's address (`&p->next`), which is the "pointer to pointer" list idiom.

### 10.9 Doubly linked list (generic)

```c
struct dnode { struct dnode *next; struct dnode *prev; int val; };
void unlink(struct dnode *n) {
    n->prev->next = n->next;
    n->next->prev = n->prev;
}
```

```asm
    mov     eax, [ebp+8]            ; n
    mov     ecx, [eax+4]            ; n->prev
    mov     edx, [ebp+8]
    mov     eax, [edx]              ; n->next
    mov     [ecx], eax              ; n->prev->next = n->next
    mov     ecx, [ebp+8]
    mov     edx, [ecx]              ; n->next
    mov     eax, [ebp+8]
    mov     ecx, [eax+4]            ; n->prev
    mov     [edx+4], ecx            ; n->next->prev = n->prev
```

Two cross-writes (`[A] = B` and `[B+4] = A`) are an unlink. If an attacker controls `next` and `prev`, this is a classic **write-what-where** primitive, which is why modern implementations add the check in 10.10.

### 10.10 Windows `LIST_ENTRY` and safe unlinking

```c
typedef struct _LIST_ENTRY { struct _LIST_ENTRY *Flink, *Blink; } LIST_ENTRY;   // Flink +0, Blink +4
RemoveEntryList(&obj->Links);
```

```asm
    mov     ecx, [eax]              ; Flink = Entry->Flink
    mov     edx, [eax+4]            ; Blink = Entry->Blink
    cmp     [ecx+4], eax            ; Flink->Blink == Entry ?
    jnz     short corrupt
    cmp     [edx], eax              ; Blink->Flink == Entry ?
    jnz     short corrupt
    mov     [edx], ecx              ; Blink->Flink = Flink
    mov     [ecx+4], edx            ; Flink->Blink = Blink
    ...
corrupt:
    mov     ecx, 3                  ; FAST_FAIL_CORRUPT_LIST_ENTRY
    int     29h                     ; __fastfail
```

`InsertHeadList` / `InsertTailList` are four pointer writes linking the entry between the head and its neighbor.

### 10.11 `CONTAINING_RECORD` (list entry embedded mid-struct)

```c
typedef struct { int id; char name[16]; LIST_ENTRY Links; } OBJ;      // Links at +14h
for (e = head.Flink; e != &head; e = e->Flink) {
    OBJ *o = CONTAINING_RECORD(e, OBJ, Links);
    if (o->id == want) ...
}
```

```asm
    mov     esi, dword ptr [head]   ; e = head.Flink
lp: cmp     esi, offset head        ; circular: stop when back at the head (no NULL test!)
    jz      short done
    lea     eax, [esi-14h]          ; o = e - offsetof(OBJ, Links)
    cmp     [eax], edi              ; o->id == want
    jz      short found
    mov     esi, [esi]              ; e = e->Flink
    jmp     short lp
```

A **negative** offset from a list pointer (`[esi-14h]`) means `CONTAINING_RECORD`. The fields are accessed relative to the start of the enclosing struct, so set the struct type at the subtracted base. A loop that ends on `cmp ptr, &head` rather than a NULL test means a circular list with a sentinel head.

### 10.12 PEB module list walk (shellcode classic)

```c
// PEB->Ldr->InInitializationOrderModuleList -> find kernel32 base
```

```asm
    xor     ecx, ecx
    mov     eax, fs:[ecx+30h]       ; PEB
    mov     eax, [eax+0Ch]          ; PEB->Ldr (PEB_LDR_DATA)
    mov     esi, [eax+1Ch]          ; Ldr->InInitializationOrderModuleList.Flink
next_mod:
    mov     ebx, [esi+8]            ; entry->DllBase        (relative to InInitOrderLinks)
    mov     edi, [esi+20h]          ; entry->BaseDllName.Buffer (UTF-16 name)
    mov     esi, [esi]              ; Flink -> next module
    cmp     [edi+0Ch*2], cx         ; name[12] == 0 ?  ("kernel32.dll" is 12 chars)
    jnz     short next_mod
```

| x86 offsets | Field |
|---|---|
| `PEB+0Ch` | `Ldr` |
| `Ldr+0Ch` / `+14h` / `+1Ch` | `InLoadOrder` / `InMemoryOrder` / `InInitializationOrder` module lists |
| `LDR_DATA_TABLE_ENTRY+18h` | `DllBase` (= `+10h` from InMemoryOrderLinks, `+8` from InInitOrderLinks) |
| `LDR_DATA_TABLE_ENTRY+30h` | `BaseDllName.Buffer` (= `+28h` from InMemoryOrderLinks, `+20h` from InInitOrderLinks) |

Different offsets for the same field depend on **which** link field the walk is using, which is the same idea as `CONTAINING_RECORD`.

### 10.13 SEH chain walk (a linked list on the stack)

```c
EXCEPTION_REGISTRATION_RECORD *r = (void*)__readfsdword(0);
while (r != (void*)-1) { ...r->Handler...; r = r->Next; }
```

```asm
    mov     eax, large fs:0         ; head
lp: cmp     eax, 0FFFFFFFFh         ; end-of-chain marker is -1, not NULL
    jz      short done
    mov     ecx, [eax+4]            ; r->Handler
    ...
    mov     eax, [eax]              ; r = r->Next   (nSEH in exploit terms)
    jmp     short lp
```

This is the list that an SEH overwrite corrupts: `[eax]` is **nSEH** and `[eax+4]` is **SEH**. In WinDbg, `!exchain` walks it for you.

### 10.14 C++ `std::list` (MSVC layout)

```cpp
std::list<int> l;   for (int v : l) sum += v;
```

| Object | Layout |
|---|---|
| `std::list<T>` (8 bytes) | `+0` `_Myhead` (pointer to the sentinel node), `+4` `_Mysize` |
| node | `+0` `_Next`, `+4` `_Prev`, `+8` `_Myval` (T) |

```asm
    mov     ecx, [ebp-l]            ; _Myhead (sentinel)
    mov     eax, [ecx]              ; it = head->_Next   (begin)
lp: cmp     eax, ecx                ; it != end()  (sentinel)
    jz      short done
    add     edx, [eax+8]            ; sum += it->_Myval
    mov     eax, [eax]              ; ++it
    jmp     short lp
```

`std::list::size()` is just a load of `[obj+4]`. In debug builds every iterator operation is a call to `_Unchecked_begin`, `operator++` and similar functions, which is noisy but shows the names.

### 10.15 Linked-list recognition summary

| Asm shape | Meaning |
|---|---|
| `mov eax, [eax+N]` in a loop + `test eax,eax ; jnz` | singly linked traversal (`next` at +N) |
| `cmp esi, offset head ; jz` ending a loop | circular list with sentinel (LIST_ENTRY, std::list) |
| `cmp eax, 0FFFFFFFFh` ending a loop | SEH chain |
| `lea eax, [esi-N]` on each node | CONTAINING_RECORD: real struct starts N bytes earlier |
| `[A]=B ; [B+4]=A` cross-writes | doubly linked unlink (write-what-where if unchecked) |
| `cmp [ecx+4], eax ; jnz ; ... int 29h` | safe unlink check (`__fastfail`) |
| `push SIZE ; call malloc` then `[eax+N]` writes | node allocation: gives sizeof and field offsets |
| two pointer vars updated in lockstep | prev/cur deletion or reversal |
| `add reg, N` (address, not load) assigned to a `**` | `pp = &(*pp)->next` idiom |
| read of `[p+N]` after `call free(p)` | use-after-free bug |

---

## 11. Functions, pointers to functions and imports

### 11.1 Direct, indirect and import calls

```c
f();            // call _f                       (direct, relative E8)
fp();           // mov eax,[ebp-4] ; call eax    or  call dword ptr [ebp-4]
obj->cb(x);     // push x ; mov ecx,[obj] ; mov edx,[ecx+8] ; call edx
CreateFileA();  // call ds:__imp__CreateFileA@28 (FF 15, through the IAT)
```

Some binaries call through thunks: `call j_CreateFileA`, where the thunk is `jmp ds:__imp__CreateFileA@28` (FF 25).

### 11.2 Runtime API resolution (common in shellcode and malware)

```c
p = GetProcAddress(LoadLibraryA("user32.dll"), "MessageBoxA");  p(0, "x", "y", 0);
```

```asm
    push    offset aUser32Dll
    call    ds:__imp__LoadLibraryA@4
    push    offset aMessageboxa
    push    eax
    call    ds:__imp__GetProcAddress@8
    mov     [ebp-4], eax
    ...
    call    dword ptr [ebp-4]   ; indirect call with no IAT entry
```

### 11.3 Control Flow Guard (`/guard:cf`) indirect calls

```asm
    mov     esi, [ebp-4]        ; target
    mov     ecx, esi
    call    ds:___guard_check_icall_fptr   ; validates ECX
    call    esi
```

### 11.4 Callback arrays / dispatch tables

```c
handlers[cmd](buf);
```

```asm
    mov     eax, [ebp-cmd]
    mov     ecx, ds:off_404000[eax*4]   ; table in .rdata/.data
    lea     edx, [ebp-buf]
    push    edx                         ; buf
    call    ecx
    add     esp, 4
```

An unchecked `cmd` here means control-flow hijack through an out-of-bounds index.

### 11.5 Recursion and tail calls

```c
int fact(int n) { return n <= 1 ? 1 : n * fact(n - 1); }
```

```asm
    ...
    mov     eax, [ebp+8]
    sub     eax, 1
    push    eax
    call    _fact               ; calls itself
    add     esp, 4
    imul    eax, [ebp+8]
```

An optimized tail call `return g(x);` becomes `jmp _g` instead of `call` followed by `ret`.

---

## 12. Windows / MSVC-specific constructs

### 12.1 Stack cookie (`/GS`)

```asm
    push    ebp
    mov     ebp, esp
    sub     esp, 48h
    mov     eax, ___security_cookie
    xor     eax, ebp
    mov     [ebp-4], eax        ; cookie stored just below saved EBP
    ...
    mov     ecx, [ebp-4]
    xor     ecx, ebp
    call    @__security_check_cookie@4
    mov     esp, ebp
    pop     ebp
    ret
```

If a function has this, a linear overflow to the return address will be caught. Look for an SEH path or an index or pointer write instead.

### 12.2 `__try / __except` (SEH, `_except_handler4`)

```asm
    push    ebp
    mov     ebp, esp
    push    0FFFFFFFEh          ; trylevel = TRYLEVEL_NONE (-2)
    push    offset stru_402360  ; scope table (encoded with the cookie in SEH4)
    push    offset __except_handler4
    mov     eax, large fs:0
    push    eax                 ; Next  -> EXCEPTION_REGISTRATION on the stack
    sub     esp, 18h
    ...
    lea     eax, [ebp-10h]
    mov     large fs:0, eax     ; link the record into the SEH chain
    mov     dword ptr [ebp-4], 0     ; entering __try block #0
    ...
    mov     dword ptr [ebp-4], 0FFFFFFFEh ; leaving __try
    ...
    mov     ecx, [ebp-10h]
    mov     large fs:0, ecx     ; unlink in the epilogue
```

`fs:0` reads and writes in a prologue mean an SEH frame. Its record (`Next`, `Handler`) sits **above** the locals, so a long overflow reaches it. That is the nSEH/SEH overwrite.

### 12.3 C++ exception frame (`try/catch`, or any function with destructible locals)

```asm
    push    ebp
    mov     ebp, esp
    push    0FFFFFFFFh          ; state = -1
    push    offset __ehhandler$?func@@YAXXZ   ; -> __CxxFrameHandler3
    mov     eax, large fs:0
    push    eax
    mov     large fs:0, esp
    ...
    mov     dword ptr [ebp-4], 0   ; state updates as objects are constructed
```

`throw` becomes a call to `__CxxThrowException@8` with a pointer to the exception object and its `_ThrowInfo`.

### 12.4 TEB / PEB access

```asm
mov eax, large fs:18h       ; TEB self pointer     (NtCurrentTeb)
mov eax, large fs:30h       ; PEB
movzx eax, byte ptr [eax+2] ; PEB->BeingDebugged   (IsDebuggerPresent inline)
mov eax, [eax+0Ch]          ; PEB->Ldr             (module list walking, shellcode)
mov eax, large fs:0         ; head of the SEH chain
mov eax, large fs:34h       ; LastErrorValue       (GetLastError inline)
```

### 12.5 Finding `main` from the entry point

The entry point is `_mainCRTStartup` (console) or `_WinMainCRTStartup` (GUI), which calls `__scrt_common_main_seh` (or `__tmainCRTStartup` in older binaries). Look for the call that pushes three values (`envp`, `argv`, `argc`) and whose return value is passed straight to `_exit`/`exit`:

```asm
    push    dword ptr [envp]
    push    dword ptr [argv]
    push    dword ptr [argc]
    call    _main
    add     esp, 0Ch
    push    eax
    call    _exit
```

For `WinMain` you'll see 4 pushes: `nShowCmd`, `lpCmdLine`, `hPrevInstance = 0`, and `hInstance` (the image base, `400000h` for a typical EXE without ASLR relocation). Global C++ constructors run before this from `_initterm`, which walks a table of function pointers.

### 12.6 `alloca` / variable-size stack buffer

```asm
    mov     eax, [ebp-len]
    call    __alloca_probe_16   ; or __chkstk; adjusts ESP by EAX (aligned)
    mov     [ebp-buf], esp      ; buffer = new ESP
```

### 12.7 Winsock server shape (typical exam target)

```asm
call ds:__imp__WSAStartup@8
call ds:__imp__socket@12
call ds:__imp__bind@12
call ds:__imp__listen@8
call ds:__imp__accept@12      ; loop: accept -> CreateThread/_beginthread(handler, sock)
...
push 0                        ; flags
push 1000h                    ; len
lea  eax, [ebp-1010h]         ; buf
push eax
push [ebp-sock]
call ds:__imp__recv@16        ; trace EAX (bytes read) and the buffer into the handler
```


### 12.8 Win32 structure setup before an API call (`cb` / `dwSize`) ★

Many Win32 APIs require the caller to zero a struct and write its own size into the first field:

```c
STARTUPINFOA si;  memset(&si, 0, sizeof si);  si.cb = sizeof si;
CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
```

```asm
    xor     eax, eax
    mov     ecx, 11h                ; 0x11 dwords = 0x44 bytes
    lea     edi, [ebp-44h]
    rep stosd                       ; memset(&si, 0, 0x44)
    mov     dword ptr [ebp-44h], 44h   ; si.cb = 0x44   <- the size identifies the type
    lea     eax, [ebp-54h]
    push    eax                     ; &pi   (PROCESS_INFORMATION, 0x10 bytes)
    lea     ecx, [ebp-44h]
    push    ecx                     ; &si
    ...
    call    ds:__imp__CreateProcessA@40
```

The workflow is: zeroed local, then a size constant written to its first field, then a pointer passed to an API. Look up which struct has that size (or check the API's documentation), then apply the type in IDA with `Alt+Q`.

| sizeof (x86) | Structure | Typical API |
|---|---|---|
| `0x10` | `sockaddr_in`, `PROCESS_INFORMATION` | `bind`/`connect`, `CreateProcess` |
| `0x44` | `STARTUPINFOA` | `CreateProcessA` |
| `0x94` | `OSVERSIONINFOA` | `GetVersionExA` |
| `0x128` | `PROCESSENTRY32` | `Process32First/Next` |
| `0x190` | `WSADATA` | `WSAStartup` |
| `0x224` | `MODULEENTRY32` | `Module32First/Next` |

The `sockaddr_in` setup in a TCP server looks like this:

```asm
    mov     word ptr [ebp-10h], 2   ; sin_family = AF_INET
    push    270Fh                   ; 9999
    call    ds:__imp__htons@4
    mov     [ebp-0Eh], ax           ; sin_port   -> the listening port
    mov     dword ptr [ebp-0Ch], 0  ; sin_addr = INADDR_ANY
```

### 12.9 Common anti-analysis checks you'll meet ★

| Pattern | Check |
|---|---|
| `sidt fword ptr [ebp-8]` then compare the IDT base against a range | "Red Pill" VM detection (old) |
| `mov eax, 1 ; cpuid ; bt ecx, 1Fh` | hypervisor-present bit |
| `call IsDebuggerPresent`, or `mov eax, fs:[30h]` then `movzx eax, byte ptr [eax+2]` | debugger check (PEB `BeingDebugged`) |
| `rdtsc … rdtsc ; sub ; cmp` | timing check (single-stepping is slow) |
| `CreateToolhelp32Snapshot` + `Process32Next` loop + `_stricmp` | looking for a process by name (analysis tools, or `explorer.exe`) |
| `push offset handler ; push fs:[0] ; mov fs:[0], esp ; int 3` | SEH-based debugger detection |

In OSED targets these show up mostly as obstacles in the path to the bug. Note them, patch around them in the debugger, and move on.

---

## 13. C++ constructs

### 13.1 Object creation and the constructor

```cpp
Derived *d = new Derived(5);
```

```asm
    push    10h                 ; sizeof(Derived)
    call    ??2@YAPAXI@Z        ; operator new(size_t)
    add     esp, 4
    mov     [ebp-8], eax
    cmp     dword ptr [ebp-8], 0
    jz      short null_
    push    5
    mov     ecx, [ebp-8]        ; this
    call    ??0Derived@@QAE@H@Z ; constructor, returns this in EAX
```

Inside the constructor:

```asm
    mov     [ebp-4], ecx        ; save this
    mov     ecx, [ebp-4]
    call    ??0Base@@QAE@XZ     ; base constructor first
    mov     eax, [ebp-4]
    mov     dword ptr [eax], offset ??_7Derived@@6B@   ; install vftable (vptr at +0)
    mov     ecx, [ebp-4]
    mov     edx, [ebp+8]
    mov     [ecx+4], edx        ; member init
    mov     eax, [ebp-4]        ; return this
```

The `cmp`/`jz` NULL check after `operator new` appears in older MSVC code; modern `new` throws `std::bad_alloc` instead of returning NULL, so the check is often absent.

A pointer to a `.rdata` table written to `[this+0]` is a vtable assignment, which identifies a constructor or destructor. Each vtable entry is a virtual method.

### 13.2 Virtual call

```cpp
obj->speak();      // 3rd virtual method
```

```asm
    mov     eax, [ebp-8]        ; obj
    mov     edx, [eax]          ; vptr
    mov     ecx, [ebp-8]        ; this
    mov     eax, [edx+8]        ; vtable slot 2 (offset / 4)
    call    eax
```

The `mov reg, [obj]` → `call [reg+N]` shape is a virtual call. An overflow into `[obj]` controls the vptr.

### 13.3 Non-virtual method and static method

```cpp
obj.get();        // lea ecx, [ebp-10h] ; call ?get@Obj@@QAEHXZ   (direct call, ECX = this)
Obj::util(1);     // push 1 ; call ?util@Obj@@SAXH@Z ; add esp,4    (no ECX: static)
```

### 13.4 delete and destructors

```cpp
delete d;          // virtual destructor
```

```asm
    mov     ecx, [ebp-8]
    mov     edx, [ecx]
    push    1                   ; flag: 1 = free memory after destruction
    mov     ecx, [ebp-8]
    call    dword ptr [edx]     ; scalar deleting destructor ??_GDerived@@UAEPAXI@Z (vtable slot 0)
```

The scalar deleting destructor runs `~Derived()`, then `if (flags & 1) operator delete(this)` (`??3@YAXPAX@Z`). Stack objects simply get a direct `call ??1Obj@@QAE@XZ` at scope exit.

### 13.5 Multiple inheritance: `this` adjustment

```asm
    lea     ecx, [eax+8]        ; cast Derived* -> SecondBase* (subobject at +8)
    ; or a thunk:  sub ecx, 8 ; jmp ?method@Derived@@...  ("adjustor thunk")
```

### 13.6 References

`int &r = x;` compiles exactly like `int *r = &x;`, with implicit dereferences. There is no difference in the assembly.

### 13.7 MSVC STL layouts (x86 release builds)

| Type | Layout |
|---|---|
| `std::string` (0x18 bytes) | `+0` union { `char buf[16]` / `char *ptr` }, `+10h` size, `+14h` capacity. If capacity ≥ 16 the data is on the heap (via `ptr`), otherwise inline (SSO) |
| `std::wstring` | same, but the inline buffer holds 8 `wchar_t` |
| `std::vector<T>` (0xC) | `+0` first, `+4` last, `+8` end of storage. `size = (last - first) / sizeof(T)` → `sub` + `sar` |
| `std::unique_ptr<T>` | a single pointer |
| `std::shared_ptr<T>` (8) | `+0` object pointer, `+4` control block (refcount `lock xadd`) |

The `(last - first) >> 2` pattern followed by `cmp` is `vec.size()`.

### 13.8 Function-local static (thread-safe init)

```asm
    mov     eax, ds:__tls_index
    mov     ecx, large fs:2Ch   ; TLS array
    ...
    cmp     ds:dword_guard, ...
    push    offset dword_guard
    call    __Init_thread_header
    ...
    call    __Init_thread_footer
```

### 13.9 RTTI and dynamic_cast

```asm
    push    0                   ; isReference
    push    offset ??_R0?AVDerived@@@8   ; target type descriptor
    push    offset ??_R0?AVBase@@@8      ; source type descriptor
    push    0                   ; vfDelta
    push    eax                 ; object
    call    ___RTDynamicCast
```

Type descriptors (`??_R0?AV<ClassName>@@`) reveal class names even in stripped binaries.

---

## 14. Floating point

### 14.1 SSE2 (default since VS2012, `/arch:SSE2`)

```c
float f = a * 2.5f;
```

```asm
    cvtsi2ss xmm0, dword ptr [ebp+8]     ; int -> float
    mulss   xmm0, ds:__real@40200000     ; 2.5f as an IEEE constant in .rdata
    movss   dword ptr [ebp-4], xmm0
```

```c
int i = (int)d;     // cvttsd2si eax, xmm0     (truncate double -> int)
if (x < y)          // comiss xmm0, xmm1 ; jae skip    <- FP compares set CF/ZF, so they use
                    //                                     "unsigned" jumps (jb/ja), not jl/jg
```

### 14.2 x87 (older builds and return values)

```asm
    fild    dword ptr [ebp+8]   ; push int as float
    fmul    ds:__real@4004000000000000   ; * 2.5 (double)
    fstp    dword ptr [ebp-4]   ; store and pop
    ...
    fld     dword ptr [ebp-4]   ; float return value left in ST(0)
```

Older float-to-int conversion calls `__ftol2` / `__ftol2_sse`. In the `__real@XXXXXXXX` names, the hex is the IEEE-754 bit pattern of the constant.

---

## 15. Miscellaneous patterns

### 15.1 `volatile` and memory barriers

```asm
lock xadd [ecx], eax          ; InterlockedExchangeAdd / refcount ++
lock cmpxchg [ecx], edx       ; InterlockedCompareExchange (lock-free, spinlocks)
xchg eax, [ecx]               ; InterlockedExchange (xchg with memory is implicitly locked)
```

`volatile` variables are reloaded from memory on every access, even at `/O2`.

### 15.2 Intrinsics and inline assembly

```asm
int 3            ; __debugbreak() / DebugBreak (CC)
rdtsc            ; __rdtsc()  -> EDX:EAX  (timing / anti-debug)
cpuid            ; __cpuid()  (VM detection)
pause            ; _mm_pause() in spin loops
ud2              ; __fastfail-style crash, unreachable code
int 29h          ; __fastfail(code) on Windows 8+ (security check failure)
```

### 15.3 Alignment padding between functions

```asm
int 3 / int 3 / int 3        ; CC padding (MSVC)
nop / lea esi,[esi+0]        ; multi-byte NOPs (GCC/MinGW)
```

### 15.4 Global and static data sections

| Section | Contents |
|---|---|
| `.text` | code |
| `.rdata` | string literals, constants, vtables, jump tables, IAT, `__real@` floats |
| `.data` | initialized globals and statics |
| `.bss` (merged into `.data` in MSVC) | zero-initialized globals |
| `.tls` | thread-local storage |
| `.reloc` | relocations (present means the image can be relocated; check ASLR with `DllCharacteristics`) |

### 15.5 Compiler register-zeroing and idioms

```asm
xor   eax, eax          ; eax = 0
or    eax, 0FFFFFFFFh   ; eax = -1
test  eax, eax          ; compare with 0
lea   eax, [ecx+4]      ; arithmetic without touching flags (eax = ecx + 4)
neg eax ; sbb eax, eax  ; eax = (eax != 0) ? -1 : 0
cdq ; xor eax,edx ; sub eax,edx   ; abs(eax)
movzx eax, al           ; widen a bool/char result
```

---

## 16. Quick recognition table

| You see | It's probably |
|---|---|
| `ret N` | stdcall/thiscall callee with N/4 args |
| `add esp, N` after a call | cdecl call with N/4 args |
| ECX used before set | thiscall (C++ method) or fastcall |
| `lea` of a stack slot pushed as an arg | passing a local buffer (likely output/destination) |
| `mov [reg], offset ??_7...` | vtable assignment in a constructor/destructor |
| `mov eax,[ecx] ; call [eax+N]` | virtual call |
| `cdq ; idiv` / `xor edx,edx ; div` | signed / unsigned division |
| `mov eax, 0CCCCCCCDh ; mul` | unsigned divide by 5 or 10 (check the shift) |
| `movsx` / `movzx` | signed / unsigned char or short |
| `jl/jg` vs `jb/ja` | signed vs unsigned compare |
| `cmp x, N ; ja default ; jmp [tbl+x*4]` | switch with jump table |
| backward `jmp` / `jcc` | loop |
| `rep stosd` / `rep movsd` | inlined memset / memcpy |
| `repne scasb` + `not ecx` | inlined strlen |
| byte load/store loop until 0 | inlined strcpy (no import entry) |
| `fs:0` read/write in prologue | SEH frame (`__try`, or C++ EH) |
| `___security_cookie ^ ebp` | /GS stack cookie |
| `call __chkstk` in prologue | stack frame larger than 4 KB |
| `add`/`adc`, `sub`/`sbb` pairs | `long long` arithmetic on EDX:EAX |
| `__allmul`, `__alldiv`, `__aullrem` … | `long long` multiply/divide/modulo helpers |
| `fs:30h` | PEB access (anti-debug, module walking) |
| `__real@...` constant | float/double literal |
| `sbb reg, reg` | boolean from carry flag (unsigned compare, `!= 0`) |
| `push imm8 ; pop reg` | size-optimized constant load (often a loop count) |
| `call $+5 ; pop reg` / `fnstenv [esp-0Ch]` | GetPC: code finding its own address (shellcode) |
| `ror reg, 0Dh ; add reg, eax` in a string loop | ROR-13 API hashing (shellcode resolving imports) |
| `lods → op → stos → loop` | XOR/arith decoder or simple cipher |
| `mov dword ptr [local], <sizeof>` right after a zeroing loop | Win32 struct `cb`/`dwSize` init (size identifies the type) |
| `dec eax ; jz` chain | switch on small consecutive values (e.g. `fdwReason`) |
| `sidt`, `cpuid`, `rdtsc` pairs | anti-VM / anti-debug checks |

---

## 17. Annotated walk-through: from assembly back to C ★

Here is a full MSVC `/Od /GS-` function in the style of an OSED target. Read the listing first and try to reconstruct it before reading the notes.

```asm
                ; int __cdecl sub_401000(SOCKET, char *, int)
01  push    ebp
02  mov     ebp, esp
03  sub     esp, 0C0h
04  cmp     dword ptr [ebp+10h], 5
05  jge     short loc_check
06  or      eax, 0FFFFFFFFh
07  jmp     short loc_exit
            loc_check:
08  push    8
09  push    offset aSetname         ; "SETNAME "
10  mov     eax, [ebp+0Ch]
11  push    eax
12  call    _strncmp
13  add     esp, 0Ch
14  test    eax, eax
15  jnz     short loc_unknown
16  mov     ecx, [ebp+0Ch]
17  add     ecx, 8
18  push    ecx
19  lea     edx, [ebp-0C0h]
20  push    edx
21  call    _strcpy
22  add     esp, 8
23  lea     eax, [ebp-0C0h]
24  push    eax
25  call    _strlen
26  add     esp, 4
27  push    eax
28  push    offset aOkD             ; "OK %d\n"
29  lea     ecx, [ebp-40h]
30  push    ecx
31  call    _sprintf
32  add     esp, 0Ch
33  push    0
34  lea     edx, [ebp-40h]
35  push    edx
36  call    _strlen
37  add     esp, 4
38  push    eax
39  lea     eax, [ebp-40h]
40  push    eax
41  mov     ecx, [ebp+8]
42  push    ecx
43  call    ds:__imp__send@16
44  mov     eax, 1
45  jmp     short loc_exit
            loc_unknown:
46  push    0
47  push    8
48  push    offset aUnknown         ; "UNKNOWN\n"
49  mov     edx, [ebp+8]
50  push    edx
51  call    ds:__imp__send@16
52  xor     eax, eax
            loc_exit:
53  mov     esp, ebp
54  pop     ebp
55  retn
```

**Notes:**

* **Lines 1–3** are a standard frame with 0xC0 bytes of locals. There is no `___security_cookie`, so the function has no /GS protection.
* **Lines 4–7** read the third argument (`[ebp+10h]`). `jge` makes it a signed int. If it is below 5, the function returns `-1` (the `or eax, 0FFFFFFFFh`), so this is a minimum-length guard.
* **Lines 8–15** call `strncmp(arg2, "SETNAME ", 8)`, so arg 2 is a `char *` (the request). If the prefix doesn't match, execution goes to `loc_unknown`.
* **Lines 16–22** compute `req + 8` (the text after the command) and call `strcpy(local_C0, req + 8)`. The local at `ebp-0C0h` is a char buffer, and **nothing checks its length**.
* **Lines 23–32** call `sprintf(local_40, "OK %d\n", strlen(local_C0))`. That makes `ebp-40h` a second buffer of 0x40 bytes, since it ends where the saved EBP begins.
* **Lines 33–43** call `send(arg1, local_40, strlen(local_40), 0)`. The arguments are pushed right to left, so arg 1 is the `SOCKET`. There's no `add esp` after the call because `send` is stdcall. The function then returns 1.
* **Lines 46–52** send `"UNKNOWN\n"` (8 bytes) and return 0.
* **Line 55** is a plain `retn`, so the function is cdecl and its caller cleans up the stack.

**Stack layout:**

```
[ebp+10h]  int    len
[ebp+0Ch]  char  *req
[ebp+8]    SOCKET s
[ebp+4]    return address        <- 0xC0 + 4 = 196 bytes after the start of arg
[ebp]      saved EBP             <- 192 bytes after the start of arg
[ebp-40h]  char reply[64]
[ebp-0C0h] char arg[128]
```

**Reconstructed C:**

```c
int handle_cmd(SOCKET s, char *req, int len)
{
    char arg[128];
    char reply[64];

    if (len < 5)
        return -1;
    if (strncmp(req, "SETNAME ", 8) == 0) {
        strcpy(arg, req + 8);                       /* stack overflow */
        sprintf(reply, "OK %d\n", (int)strlen(arg));
        send(s, reply, (int)strlen(reply), 0);
        return 1;
    }
    send(s, "UNKNOWN\n", 8, 0);
    return 0;
}
```

**Exploitation notes:**

* **Overflow and offset:** `strcpy` into a 128-byte buffer. EIP is overwritten after **196** bytes of payload, which means "SETNAME " followed by 196 bytes and then the new EIP.
* **Bad characters:** at least `00` (it's a `strcpy`), plus anything the receive or parsing code before this function cuts on.
* **Arguments above the return address:** payload bytes after the new EIP overwrite `s`, `req` and `len` (`[ebp+8]` onwards). Only `s` is used again before `ret`, in `send`, and an invalid socket just makes `send` fail, so the function still reaches `ret`. Always check which arguments a function uses after the overflow.
* **`reply` is overwritten after the overflow:** `reply` lies between `arg` and the saved EBP. After `strcpy` returns, `sprintf` writes `"OK <n>\n"` into `reply`, so payload bytes **128 to about 136** get overwritten before `ret`. Don't put shellcode or gadget addresses there. Pad over that area or jump past it.

---

## 18. Practice exercises ★

The answers are hidden below each question. Exercises 1, 2 and 8 were checked by assembling the code and running it.

**1.** What are the argument types, and what does this cdecl function do?

```asm
    push    esi
    push    edi
    mov     esi, [esp+0Ch]
    mov     edi, [esp+10h]
    mov     ecx, [esp+14h]
    jecxz   done
lp: lodsb
    xor     al, 0AAh
    stosb
    loop    lp
done:
    pop     edi
    pop     esi
    ret
```

<details><summary>Answer</summary>

The arguments are at `+0Ch`, `+10h` and `+14h`, because two pushes and the return address come first. The function is `void f(const uint8_t *src, uint8_t *dst, size_t n)`. It copies `n` bytes from `src` to `dst`, XORing each byte with `0xAA`, which makes it a single-byte XOR encoder/decoder.

</details>

**2.** What does this function return?

```asm
    push    edi
    mov     edi, [esp+8]
    mov     al, [esp+0Ch]
    mov     ecx, [esp+10h]
    jecxz   nf
    repne scasb
    jnz     nf
    lea     eax, [edi-1]
    jmp     out
nf: xor     eax, eax
out:
    pop     edi
    ret
```

<details><summary>Answer</summary>

It is `memchr(buf, c, n)`. It scans up to `n` bytes for `c`. After a match, EDI points one byte *past* the match, so it returns `edi - 1`, or NULL if nothing matched.

</details>

**3.** What does this compute?

```asm
    mov     eax, 0CCCCCCCDh
    mul     ecx
    shr     edx, 2
    mov     eax, edx
```

<details><summary>Answer</summary>

`ECX / 5`, unsigned. The magic number `0xCCCCCCCD` with a total shift of 32 + 2 means division by 5 (with a shift of 3 it would be division by 10).

</details>

**4.** `struct { uint8_t a; uint8_t b; uint16_t c; } *p` is in ECX. What values does `mov dword ptr [ecx], 0A0102h` assign?

<details><summary>Answer</summary>

The bytes in memory are `02 01 0A 00`, so `a = 2`, `b = 1` and `c = 0x000A`.

</details>

**5.** A function ends with `ret 0Ch`, and its first instruction that uses ECX reads it (`mov esi, ecx`). What is its calling convention, and how many stack arguments does it take?

<details><summary>Answer</summary>

It is `__thiscall`, with `this` in ECX (or fastcall if EDX is also read before being written). It has 3 stack arguments, since 0xC / 4 = 3, and the callee cleans them up.

</details>

**6.** Give two ways to read EIP and three ways to transfer control to `0x41414141`.

<details><summary>Answer</summary>

See §2.8. To read EIP, use `call $+5 ; pop eax`, the jmp/call/pop variant, or `fnstenv`. To transfer control, use `jmp reg`, `call reg`, or `push 41414141h ; ret`.

</details>

**7.** In §17, why would a payload with a valid return address still crash if it placed shellcode right after 128 bytes of padding?

<details><summary>Answer</summary>

Because `sprintf` writes `"OK <n>\n"` into `reply[]`, which starts exactly 128 bytes into the payload, after `strcpy` has run but before the function returns. Those bytes are overwritten.

</details>

**8.** Write `strlen`, `strchr`, `strcmp`, `memset` and `memcpy` in x86 (cdecl), then compare your versions with these.

<details><summary>Reference solutions</summary>

```asm
_my_strlen:                     ; size_t my_strlen(const char *s)
    mov     ecx, [esp+4]
    mov     eax, ecx
l1: cmp     byte ptr [eax], 0
    je      d1
    inc     eax
    jmp     l1
d1: sub     eax, ecx
    ret

_my_strchr:                     ; char *my_strchr(const char *s, int c)
    mov     eax, [esp+4]
    mov     dl, [esp+8]
l2: mov     cl, [eax]
    cmp     cl, dl
    je      f2                  ; also handles c == 0 (returns the terminator)
    test    cl, cl
    jz      n2
    inc     eax
    jmp     l2
n2: xor     eax, eax
f2: ret

_my_strcmp:                     ; int my_strcmp(const char *a, const char *b)
    mov     ecx, [esp+4]
    mov     edx, [esp+8]
l3: mov     al, [ecx]
    cmp     al, [edx]
    jne     df
    test    al, al
    jz      eq
    inc     ecx
    inc     edx
    jmp     l3
eq: xor     eax, eax
    ret
df: sbb     eax, eax            ; flags still from cmp: -1 if a < b (unsigned)
    or      eax, 1              ; -> -1 or 1
    ret

_my_memset:                     ; void *my_memset(void *d, int c, size_t n)
    push    edi
    mov     edi, [esp+8]
    movzx   eax, byte ptr [esp+0Ch]
    mov     ecx, [esp+10h]
    mov     edx, edi
    rep stosb
    mov     eax, edx
    pop     edi
    ret

_my_memcpy:                     ; void *my_memcpy(void *d, const void *s, size_t n)
    push    esi
    push    edi
    mov     edi, [esp+0Ch]
    mov     esi, [esp+10h]
    mov     ecx, [esp+14h]
    mov     eax, edi
    mov     edx, ecx
    shr     ecx, 2
    rep movsd                   ; n / 4 dwords
    mov     ecx, edx
    and     ecx, 3
    rep movsb                   ; n % 4 leftover bytes
    pop     edi
    pop     esi
    ret
```

</details>

**9.** Draw the stack (arguments, return address, saved EBP, locals) for the `_add` call traced in §2.7, writing the address of every slot.

**10.** Compile five functions from this file with `cl /Od` and with `cl /O2`, open both versions in IDA, and label every construct you recognize. Then do the same with a function from Vulnserver.
