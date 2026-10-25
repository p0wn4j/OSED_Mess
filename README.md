# OSED_Mess

Whenever we are dealing with a limited amount of space, we should first attempt to 
increase the size of the buffer we send to determine if this results in more space for our overflow.

The Problem for Position-Independent Shellcode

Position-Independent Code (PIC) must run correctly no matter where it is loaded into memory.
Because standard CALL opcodes use relative offsets, they actually help make shellcode position-independent 
when jumping within the shellcode itself. 
The exact memory location does not matter; the distance between the instructions remains constant.

WINAPI data types:
https://learn.microsoft.com/en-us/windows/win32/winprog/windows-data-types

The issue: The FPU environment data is written to the memory address pointed to by the ESP register. 
If your NOP sled is placed directly before the payload and you jump straight to it, your ESP might be 
pointing right inside your shellcode. 
When fnstenv executes, it will overwrite the payload code further down the stream with its own state data, 
corrupting the payload before it can finish decoding.
