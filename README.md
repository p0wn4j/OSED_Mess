# OSED_Mess

The Problem for Position-Independent Shellcode

Position-Independent Code (PIC) must run correctly no matter where it is loaded into memory.
Because standard CALL opcodes use relative offsets, they actually help make shellcode position-independent 
when jumping within the shellcode itself. 
The exact memory location does not matter; the distance between the instructions remains constant.
